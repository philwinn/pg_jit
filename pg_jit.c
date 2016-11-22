#include <postgres.h>
#include <libfirm/firm.h>

#include <optimizer/planner.h>
#include <executor/executor.h>
#include <utils/syscache.h>
#include <utils/builtins.h>
#include <utils/guc.h>
#include <nodes/nodeFuncs.h>

#include <dlfcn.h>

/* Assemble and link command */
#define LINK_COMMAND "gcc -shared -o %s %s"

PG_MODULE_MAGIC;

bool pg_jit_enabled;

void _PG_init(void);
void _PG_fini(void);

/* Global *_hook restore variables used by pg_jit */
static planner_hook_type prev_planner_hook;
static ExecutorRun_hook_type prev_ExecutorRun_hook;

/* Custom hook-functions used by pg_jit */
static PlannedStmt*
pg_jit_planner(Query *parse,
            int cursorOptions,
            ParamListInfo boundParams);
static void
pg_jit_ExecutorRun(QueryDesc *queryDesc,
                ScanDirection direction,
                long count);

/* Not in public Firm API */
void remove_irp_irg(ir_graph *irg);
void add_irp_irg(ir_graph *irg);
ir_graph* create_irg_copy(ir_graph *irg);
void set_entity_irg(ir_entity *ent, ir_graph *irg);

/* Must be placed in pg's data dir: */
static const char* path_to_ir = "executor.ir";

/* Is there a way to obtain F64 from the imported IR? */
ir_mode *mode_F64;

/* Custom module functions */
static void init_misc_guc();
static void init_firm();
static void prepare_jit_execution(QueryDesc *queryDesc);
static bool jit_compilation_feasible(PlannedStmt *ps);
static void jit_compile_query(PlannedStmt *ps);
static void init_planner_hook();
static void init_ExecutorRun_hook();


/* Custom types */
enum ListTag {
	T_Targetlist,
	T_Qual
};

typedef struct ExprTree
{
	List *expr_list;   /* targetlist or qual */
	enum ListTag tag;  /* type of list (targetlist or qual) */
	Node *tme;         /* Top most expression in list */
	List *vars;        /* List of all Vars from list */
	char *ld_name;     /* symbolic name of compiled functions */
	ir_graph *irg;     /* irg representing the compiled func */
} ExprTree;

typedef struct ExprTrees
{
	List *idx;         /* Simplifies iteration over trees */
	ExprTree trees[2]; /* Array of trees (targetlist/qual) */
} ExprTrees;

typedef struct Arg
{
	ir_node *node[2];  /* Array of arguments for a func call */
} Arg;

typedef struct Context
{
	int pos;
	List *children;
	ir_node *arg_ptr;
	Arg *arg;
	ir_type *param_type;
	ir_type *datum_type;
	List *var_vals;
} Context;

/* Global Vars: et, handle */
static ExprTrees et;
static void *handle;


void
_PG_init(void)
{
	prev_planner_hook = planner_hook;
	prev_ExecutorRun_hook = ExecutorRun_hook;

	init_misc_guc();
	init_firm();
	init_planner_hook();
}

void
_PG_fini(void)
{
	planner_hook = prev_planner_hook;
	ExecutorRun_hook = prev_ExecutorRun_hook;
}

static void
init_misc_guc()
{
	DefineCustomBoolVariable("pg_jit.enabled",
	                         "Enables just-in-time compilation",
	                         NULL,
	                         &pg_jit_enabled,
	                         false,
	                         PGC_USERSET,
	                         GUC_NOT_IN_SAMPLE,
	                         NULL, NULL, NULL);
}

static void
init_planner_hook()
{
	prev_planner_hook = planner_hook;
	planner_hook = pg_jit_planner;
}

static void
init_ExecutorRun_hook()
{
	prev_ExecutorRun_hook = ExecutorRun_hook;
	ExecutorRun_hook = pg_jit_ExecutorRun;
}

static PlannedStmt*
pg_jit_planner(Query *parse,
            int cursorOptions,
            ParamListInfo boundParams)
{
	PlannedStmt *result;
	result = standard_planner(parse,
	                          cursorOptions,
	                          boundParams);
	if(pg_jit_enabled)
	{
		if(jit_compilation_feasible(result))
		{
			jit_compile_query(result);
		}
		else
		{
			char *msg = "JIT compilation not feasible!";
			ereport(NOTICE, (errmsg_internal(msg)));
		}
	}
	return result;
}

static void
pg_jit_ExecutorRun(QueryDesc *queryDesc,
                   ScanDirection direction,
                   long count)
{
	if(pg_jit_enabled)
	{
		prepare_jit_execution(queryDesc);
	}
	standard_ExecutorRun(queryDesc, direction, count);
}

static void
no_codegen()
{
	for(int i = 0; i < get_irp_n_irgs(); i++)
	{
		ir_entity* ent = get_irg_entity(get_irp_irg(i));
		set_entity_linkage(ent, IR_LINKAGE_NO_CODEGEN);
		set_entity_visibility(ent, ir_visibility_private);
	}
}

/*
 * TODO: This is too expensive, find a faster way to
 * get the desired entity.
 */
static ir_entity*
get_entity(const char* ld_name)
{
	for(size_t i = 0; i < get_irp_n_irgs(); i++)
	{
		ir_graph* irg = get_irp_irg(i);
		ir_entity* ent = get_irg_entity(irg);
		if(!strncmp(get_entity_ld_ident(ent),
		            ld_name,
		            sizeof(ld_name)/sizeof(char)))
		{
			return ent;
		}
	}
	return NULL;
}

static void
get_n_call_nodes(ir_node *node, void *ptr)
{
	int *n = (int*) ptr;
	if(is_Call(node))
	{
		(*n)++;
	}
}

static void
optimize(ir_graph* irg)
{
	// dump_ir_graph(irg, "constructed");
	int n_call_nodes = 0;
	irg_walk(get_irg_end(irg),
	         NULL,
	         get_n_call_nodes,
	         &n_call_nodes);
	inline_functions(n_call_nodes*120,
	                 0,
	                 NULL);
	remove_bads(irg);
	remove_unreachable_code(irg);
	remove_tuples(irg);
	do_loop_inversion(irg);
	optimize_reassociation(irg);
	optimize_cf(irg);

	opt_parallelize_mem(irg);
	optimize_graph_df(irg);
	combo(irg);
	scalar_replacement_opt(irg);
	place_code(irg);
	optimize_reassociation(irg);
	optimize_graph_df(irg);
	opt_jumpthreading(irg);
	optimize_graph_df(irg);
	construct_confirms(irg);
	optimize_graph_df(irg);
	remove_confirms(irg);
	optimize_cf(irg);
	optimize_load_store(irg);
	optimize_graph_df(irg);
	combo(irg);
	place_code(irg);
	optimize_cf(irg);

	conv_opt(irg);
	opt_parallelize_mem(irg);
	optimize_load_store(irg);
	remove_unreachable_code(irg);
	lower_highlevel_graph(irg);

	// dump_ir_graph(irg, "optimized");
}

static void*
get_fptr(void *handle, const char* ld_name)
{
	const char* error;
	void* fptr = dlsym(handle, ld_name);
	error = dlerror();
	if(error)
	{
		char *msg = "Symbol not found!";
		ereport(ERROR, (errmsg_internal(msg)));
	}
	return fptr;
}

static void
demangle()
{
	for(size_t i = 0; i < get_irp_n_irgs(); i++)
	{
		ir_graph *irg = get_irp_irg(i);
		ir_entity* ent = get_irg_entity(irg);
		const char* ld_name = get_entity_ld_name(ent);
		if(strncmp(ld_name, "r.", 2) == 0)
		{
			size_t len = strlen(ld_name);
			char* c = (char*) ld_name;
			for(c += len*sizeof(char)-1; *c != '.'; c--);
			set_entity_ld_ident(ent, (const ident*) ++c);
		}
	}
}

static void
init_firm()
{
	ir_init();

	if(!(be_parse_arg("isa=amd64") &&
	     be_parse_arg("pic=elf")))
	{
		char *msg = "Firm backend initialization failed!";
		ereport(ERROR, (errmsg_internal(msg)));
	}
	if(ir_import(path_to_ir))
	{
		char *msg =
			"Import of executor.ir failed! Provide this file in pg's data dir.";
		ereport(ERROR, (errmsg_internal(msg)));
	}

	demangle();
	no_codegen();
}

static void*
compile()
{
	const char *ld_name = (char*) id_unique("expr");

	char filename_s[64];
	snprintf(filename_s,
	         sizeof(filename_s),
	         "pg_jit-%s.s",
	         ld_name);
	FILE *out = fopen(filename_s, "w");
	if(out == NULL) {
		char *msg = "couldn't open assembly file for writing";
		ereport(ERROR, (errmsg_internal(msg)));
	}
	be_main(out, "cup");
	fclose(out);

	char filename_so[64];
	snprintf(filename_so,
	         sizeof(filename_so),
	         "./pg_jit-%s.so", ld_name);
	{
		char command[128];
		snprintf(command,
		         sizeof(command),
		         LINK_COMMAND,
		         filename_so,
		         filename_s);
		int rc = system(command);
		if (!WIFEXITED(rc) || WEXITSTATUS(rc))
		{
			char buffer[200];
			char *msg = "assembler/linker command failed:";
			snprintf(buffer,
			         sizeof(buffer),
			         "%s %s", msg, command);
			ereport(ERROR, (errmsg_internal(buffer)));
		}
	}
	no_codegen();
	void* handle = dlopen(filename_so,
	                      RTLD_NOW|RTLD_DEEPBIND);
	const char* error = dlerror();
	if(error)
	{
		ereport(ERROR, (errmsg_internal(error)));
	}
	return handle;
}

static Datum
proxy_helper(FunctionCallInfo fcinfo)
{
	Datum datum = 0;
	return datum;
}

static Datum
proxy_func(ExprState *estate,
           ExprContext *econtext,
           bool *isNull,
           ExprDoneCond *isDone)
{
	FuncExprState *fcache = (FuncExprState*) estate->expr;
	FunctionCallInfoData *fcinfo =
		(FunctionCallInfoData*) &fcache->fcinfo_data;
	FmgrInfo *finfo = fcinfo->flinfo;
	finfo->fn_addr = proxy_helper;

	Datum datum = 0;
	return datum;
}

/* prepare_jit_execution
 * This function essentially calls the functions
 * ExecEvalFunc or ExecEvalOper and sets the custom
 * compiled function pointer.
 */
static void
prepare_jit_execution(QueryDesc *queryDesc)
{
	PlanState *planstate = queryDesc->planstate;
	List *qual = planstate->qual;
	FunctionScanState *fss = (FunctionScanState*) planstate;
	ScanState *node = &fss->ss;
	ProjectionInfo *projInfo = node->ps.ps_ProjInfo;
	List *targetlist = projInfo->pi_targetlist;
	GenericExprState *gstate =
		(GenericExprState*) lfirst(targetlist->head);
	FuncExprState *fcache = NULL;
	ExprContext *econtext = NULL;
	FmgrInfo *finfo = NULL;
	ExprState *clause = NULL;

	ListCell *cell;
	foreach(cell, et.idx)
	{
		ExprTree *tree = lfirst(cell);
		const char *ld_name = tree->ld_name;
		Datum (*evalfunc)(FuncExprState*,
		                  ExprContext*,
		                  bool*,
		                  ExprDoneCond*);
		if(tree->tag == T_Targetlist)
		{
			fcache = (FuncExprState*) gstate->arg;
			econtext = projInfo->pi_exprContext;
		}
		else if(tree->tag == T_Qual)
		{
			clause = (ExprState*) lfirst(qual->head);
			fcache = (FuncExprState*) clause;
			econtext = node->ps.ps_ExprContext;
		}

		finfo = &(fcache->func);
		ExprState *es = (ExprState*) fcache;
		evalfunc = (void*) es->evalfunc;
		bool isNull;
		ExprDoneCond isDone;

		List *args_tmp = fcache->args;
		List *dummy = NIL;
		ExprState proxy_es;
		proxy_es.expr = (Expr*) fcache;
		proxy_es.evalfunc = (ExprStateEvalFunc) proxy_func;
		dummy = lappend(dummy, &proxy_es);

		fcache->args = dummy;
		evalfunc(fcache, econtext, &isNull, &isDone);
		fcache->args = args_tmp;

		/* Set the function pointer of the compiled function */
		finfo->fn_addr = get_fptr(handle, ld_name);

		list_free(et.idx);
		et.idx = NIL;
	}
}

/* ld_name_from_oid
 * Returns symbolic name (prosrc) for an oid.
 */
static char*
ld_name_from_oid(Oid oid)
{
	HeapTuple procTup = SearchSysCache1(PROCOID,
	                                    ObjectIdGetDatum(oid));
	if(!HeapTupleIsValid(procTup))
		elog(ERROR, "cache lookup failed for function %u",
		     oid);
	bool isNULL;
	Datum res = SysCacheGetAttr(PROCOID, procTup, 25, &isNULL);
	char* prosrc = DatumGetCString(DirectFunctionCall1(textout,
	                                                   res));
	ReleaseSysCache(procTup);
	return prosrc;
}

static void
opt_after_mod(ir_graph* irg)
{
	remove_bads(irg);
	dead_node_elimination(irg);
	remove_unreachable_code(irg);
	combo(irg);
	optimize_cf(irg);
}

static void
modify_function(ir_entity *ent, int n_param)
{
	ir_graph *irg = get_entity_irg(ent);
	ir_type *ent_type = get_entity_type(ent);
	ir_type *first_param_type =
		get_method_param_type(ent_type, 0);
	if(get_type_opcode(first_param_type) != tpo_pointer)
	{
		/* return if the graph is already modified */
		return;
	}

	// dump_ir_graph(irg, "pre-mod");
	compute_irg_outs(irg);
	ir_type *datum_type = new_type_primitive(mode_Lu);
	ir_node *args = get_irg_args(irg);
	ir_node *arg_p = get_irn_out(args, 0);
	ir_type *res_type = get_method_res_type(ent_type, 0);

	ir_node *t_args = new_r_Proj(get_irg_start(irg),
	                             mode_T,
	                             pn_Start_T_args);

	ir_type *method_type = new_type_method(n_param,
	                                       1,
	                                       0,
	                                       cc_reg_param,
	                                       mtp_no_property);

	for(int i = 0; i < n_param; i++)
	{
		set_method_param_type(method_type, i, datum_type);
	}
	set_method_res_type(method_type, 0, res_type);
	set_entity_type(ent, method_type);
	set_irg_args(irg, t_args);

	for(int i = 0; i < n_param; i++)
	{
		ir_node *add = get_irn_out(arg_p, i);
		if(is_Add(add))
		{
			ir_node *add2 = get_irn_out(add, 0);
			if(is_Add(add2))
			{
				ir_node *load = get_irn_out(add2, 0);
				if(is_Load(load))
				{
					size_t irn_n = get_irn_n_outs(load);
					for(int j = 0; j < irn_n; j++)
					{
						ir_node *proj = get_irn_out(load, j);
						if(is_Proj(proj) &&
						   (get_irn_mode(proj) == mode_M))
						{
							exchange(proj, get_Load_mem(load));
						}
						else if(is_Proj(proj))
						{
							set_Proj_num(proj, i);
							set_Proj_pred(proj, t_args);
						}
					}
				}
			}
		}
	}
	opt_after_mod(irg);
	// dump_ir_graph(irg, "after-mod");
}

static void
construct_function(Node *node, Context *ctx)
{
	ir_entity *ent = NULL;
	int n_param = 0;

	if(node->type == T_FuncExpr)
	{
		FuncExpr *expr = (FuncExpr*) node;
		Oid oid = expr->funcid;
		char *ld_name = ld_name_from_oid(oid);
		ent = get_entity(ld_name);
		n_param = expr->args->length;
	}
	else if(node->type == T_OpExpr)
	{
		OpExpr *expr = (OpExpr*) node;
		Oid oid = expr->opfuncid;
		char *ld_name = ld_name_from_oid(oid);
		ent = get_entity(ld_name);
		n_param = expr->args->length;
	}
	modify_function(ent, n_param);

	set_entity_additional_properties(
		ent,
		mtp_property_always_inline);

	ir_node *store = get_store();
	ir_node *address = new_Address(ent);
	ir_node *call = new_Call(store,
	                         address,
	                         n_param,
	                         ctx->arg->node,
	                         get_entity_type(ent));
	ir_node *call_result = new_Proj(call,
	                                mode_T,
	                                pn_Call_T_result);
	set_store(store);

	ctx->arg->node[ctx->pos] = new_Proj(call_result,
	                                    mode_Lu,
	                                    0);
}

static void
construct_const(Node *node, Context *ctx)
{
	Const *expr = (Const*) node;
	ctx->arg->node[ctx->pos] = new_Const_long(mode_Lu,
	                                          expr->constvalue);
}

static void
construct_var(Node *node, Context *ctx)
{
	Var *var = (Var*) node;
	int idx = (int) var->varnoold;
	ir_node *var_val = NULL;
	ListCell *cell;
	foreach(cell, ctx->var_vals)
	{
		var_val = lfirst(cell);
		Var *var_l = get_irn_link(var_val);
		int idx_l = (int) var_l->varnoold;
		if(idx == idx_l)
		{
			break;
		}
	}
	ctx->arg->node[ctx->pos] = var_val;
}

bool targetlist_walker(Node *node, Context *ctx)
{
	if(node == NULL)
	{
		return false;
	}
	int pos = 0;
	Arg my_arg = {NULL};
	Arg *parents_arg = NULL;

	if(ctx->children != NULL)
	{
		Node *ptr = (Node*)ctx->children->head->data.ptr_value;
		pos = (node == ptr) ? 0 : 1;
		ctx->pos = pos;
	}
	if(IsA(node, FuncExpr))
	{
		FuncExpr *expr = (FuncExpr*) node;
		ctx->children = expr->args;
		ctx->arg = ctx->arg ? ctx->arg : &my_arg;
		parents_arg = ctx->arg;
		ctx->arg = &my_arg;
	}
	else if(IsA(node, OpExpr))
	{
		OpExpr *expr = (OpExpr*) node;
		ctx->children = expr->args;
		ctx->arg = ctx->arg ? ctx->arg : &my_arg;
		parents_arg = ctx->arg;
		ctx->arg = &my_arg;
	}
	bool ret = expression_tree_walker(node,
	                                  targetlist_walker,
	                                  (void*) ctx);
	ctx->pos = pos;
	if(IsA(node, FuncExpr))
	{
		ctx->arg = &my_arg;
		construct_function(node, ctx);
		parents_arg->node[pos] = ctx->arg->node[pos];
		ctx->arg = parents_arg;
	}
	else if(IsA(node, OpExpr))
	{
		ctx->arg = &my_arg;
		construct_function(node, ctx);
		parents_arg->node[pos] = ctx->arg->node[pos];
		ctx->arg = parents_arg;
	}
	else if(IsA(node, Const))
	{
		construct_const(node, ctx);
	}
	else if(IsA(node, Var))
	{
		construct_var(node, ctx);
	}
	return ret;
}

static void
finalize_construction(ir_node *return_value[])
{
	ir_node *ret_val = return_value[0];
	ir_node *store = get_store();
	ir_node *return_node = new_Return(store,
	                                  1,
	                                  &ret_val);
	ir_node *end_block = get_irg_end_block(current_ir_graph);
	add_immBlock_pred(end_block, return_node);
	mature_immBlock(get_cur_block());
	set_cur_block(NULL);
	irg_finalize_cons(current_ir_graph);
}

static ir_graph*
construct_irg(List *targetlist,
              ident *func_id,
              List *vars)
{
	ir_type *method_type = new_type_method(1,
	                                       1,
	                                       0,
	                                       cc_reg_param,
	                                       mtp_no_property);

	ir_type *param_type =
		new_type_struct((ident*) "FunctionCallInfoData");
	default_layout_compound_type(param_type);
	set_type_size(param_type, sizeof(FunctionCallInfoData));
	set_type_alignment(param_type, 8);
	ir_type *param_ptr_type = new_type_pointer(param_type);
	set_method_param_type(method_type, 0, param_ptr_type);
	ir_type *datum_type = new_type_primitive(mode_Lu);
	set_method_res_type(method_type, 0, datum_type);

	ir_entity *new_ent = new_entity(get_glob_type(),
	                                func_id,
	                                method_type);

	set_entity_ld_ident(new_ent, func_id);
	set_entity_ident(new_ent, func_id);
	ir_graph *irg = new_ir_graph(new_ent, 3);
	set_current_ir_graph(irg);

	mode_F64 = new_float_mode("F64",
	                          irma_ieee754,
	                          11,
	                          52,
	                          ir_overflow_indefinite);

	ir_node *args_node = new_Proj(get_irg_start(irg),
	                              mode_T,
	                              pn_Start_T_args);
	ir_node *arg_ptr = new_Proj(args_node,
	                            mode_P,
	                            0);

	ir_type *fcinfo_arg_type = new_type_array(datum_type,
	                                          100);
	set_type_alignment(fcinfo_arg_type, 8);

	ident *const id = id_unique("fcinfo");
	ir_entity *struct_ent = new_entity(get_glob_type(),
	                                   id,
	                                   param_type);
	ident *const arr_ent_id = id_unique("fcinfo_arg");
	ir_entity *arr_ent = new_entity(param_type,
	                                arr_ent_id,
	                                fcinfo_arg_type);
	set_entity_offset(arr_ent, 32);

	ir_node *fcinfo_arg = new_Member(arg_ptr, arr_ent);
	set_entity_visibility(struct_ent, ir_visibility_private);
	set_entity_visibility(arr_ent, ir_visibility_private);

	List *var_vals = NIL;
	ListCell *cell;
	ir_reserve_resources(irg, IR_RESOURCE_IRN_LINK);
	foreach(cell, vars)
	{
		Var *var = lfirst(cell);
		int idx = (int) var->varnoold;
		ir_node *var_idx = new_Const_long(mode_Ls, idx-1);
		ir_node *var_sel = new_Sel(fcinfo_arg,
		                           var_idx,
		                           fcinfo_arg_type);

		ir_node *store = get_store();
		ir_node *sel_load = new_Load(store,
		                             var_sel,
		                             mode_Lu,
		                             datum_type,
		                             cons_none);
		ir_node *var_val = new_Proj(sel_load,
		                            mode_Lu,
		                            pn_Load_res);
		set_irn_link(var_val, var);
		ir_node *mem = new_Proj(sel_load,
		                        mode_M,
		                        pn_Load_M);
		set_store(mem);
		var_vals = lappend(var_vals, var_val);
	}

	Context ctx;
	ctx.children = NULL;
	ctx.arg_ptr = arg_ptr;
	ctx.param_type = param_type;
	ctx.datum_type = datum_type;
	ctx.var_vals = var_vals;
	ctx.arg = NULL;

	targetlist_walker((Node*) lfirst(targetlist->head),
	                  &ctx);

	ir_free_resources(irg, IR_RESOURCE_IRN_LINK);
	finalize_construction(ctx.arg->node);

	return current_ir_graph;
}

bool tree_walker(Node *node, ExprTree *tree)
{
	if(node == NULL)
	{
		return false;
	}
	if(tree->tme == NULL &&
	   (IsA(node, FuncExpr) ||
	    IsA(node, OpExpr))
	   )
	{
		tree->tme = node;
	}

	bool res = expression_tree_walker(node,
	                                  tree_walker,
	                                  (void*) tree);
	if(IsA(node, Var))
	{
		Var *var = (Var*) node;
		bool var_in_list = false;

		ListCell *cell;
		foreach(cell, tree->vars)
		{
			Var *var_list = lfirst(cell);
			if(var->varnoold == var_list->varnoold)
			{
				var_in_list = true;
			}
		}
		if(!var_in_list)
		{
			tree->vars = lappend(tree->vars, node);
		}
	}
	return res;
}

static void
modify_tree(List *expr_trees)
{
	ListCell *cell;
	foreach(cell, expr_trees)
	{
		ExprTree *tree = lfirst(cell);
		Node *tme = tree->tme;
		if(!tme)
			break;
		NodeTag type = tme->type;
		if(type == T_FuncExpr)
		{
			FuncExpr *expr = (FuncExpr*) tme;
			expr->args = tree->vars;
		}
		else if(type == T_OpExpr)
		{
			OpExpr *expr = (OpExpr*) tme;
			expr->args = tree->vars;
		}
	}
}

static void
destroy_irg(List *expr_trees)
{
	ListCell *cell;
	foreach(cell, expr_trees)
	{
		ExprTree *tree = lfirst(cell);
		ir_graph *irg = tree->irg;
		remove_compound_member(get_glob_type(),
		                       get_irg_entity(irg));
		free_entity(get_irg_entity(irg));
		free_ir_graph(irg);
	}
}

static bool
jit_compilation_feasible(PlannedStmt *ps)
{
	static bool feasibility = false;
	Plan *plan = ps->planTree;
	List *targetlist = plan->targetlist;
	List *qual = plan->qual;

	if(IsA(plan, FunctionScan))
	{
		feasibility = true;
	}
	feasibility = !expression_returns_set((Node*) targetlist);
	feasibility = !expression_returns_set((Node*) qual);

	return feasibility;
}

/*
 * TODO: Implement query tree walker */
static void
jit_compile_query(PlannedStmt *ps)
{
	Plan *plan = ps->planTree;
	List *expr_trees = NIL;
	ExprTree tree_tl = {.vars=NIL, .tme=NULL};
	ExprTree tree_ql = {.vars=NIL, .tme=NULL};
	if(plan->targetlist)
	{
		tree_tl.expr_list = plan->targetlist;
		tree_tl.tag = T_Targetlist;
		expr_trees = lappend(expr_trees, &tree_tl);
	}
	if(plan->qual)
	{
		tree_ql.expr_list = plan->qual;
		tree_ql.tag = T_Qual;
		expr_trees = lappend(expr_trees, &tree_ql);
	}

	ListCell *cell;
	foreach(cell, expr_trees)
	{
		ExprTree *tree = lfirst(cell);
		List *expr_list = tree->expr_list;
		tree_walker((Node*) expr_list, tree);
		if(tree->tme)
		{
			ident *func_id = id_unique("expr");
			tree->ld_name = (char*) get_id_str(func_id);
			tree->irg = construct_irg(expr_list,
			                          func_id,
			                          tree->vars);
			optimize(tree->irg);
		}
		else
		{
			expr_trees = list_delete(expr_trees, tree);
		}
	}
	/* Initialize global ExprTrees struct */
	int i = 0;
	foreach(cell, expr_trees)
	{
		ExprTree *tree = lfirst(cell);
		et.trees[i] = *tree;
		et.idx = lappend(et.idx, &et.trees[i]);
		i++;
	}

	/* If length of expr_trees is 0, there is nothing
	 * to compile */
	if(expr_trees->length)
	{
		handle = compile();
		destroy_irg(expr_trees);
		modify_tree(expr_trees);
		init_ExecutorRun_hook();
	}
	else
	{
		char *msg = "JIT-compilation not feasible!";
		ereport(NOTICE, (errmsg_internal(msg)));
	}
}
