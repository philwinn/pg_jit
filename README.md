# pg_jit

As a proof of concept, this extension makes it possible to just-in-time compile
a function scan query in PostgreSQL using the implementation of the intermediate
representation Firm, libFirm.

## Dependencies

* postgresql 9.5.3,
* cparser    1.22.1(74dc24f5694ff852a1a67c06c5fc7a1f9c18765e-dirty),
* libfirm    1.22(ec5ef9e26872605e80077941e98d6024799f2900)

## Usage

* Enable pg_jit:
 * `postgres=# set pg_jit.enabled=true;`
