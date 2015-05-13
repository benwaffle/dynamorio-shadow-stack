Pin version - https://github.com/benwaffle/pin-shadow-stack

to build dynamorio:
```
$ mkdir build && cd build
$ cmake .. && make && make install
```

to build shadow stack:
```
$ mkdir build && cd build
$ cmake .. && make
```

to run shadow stack: from `build/` run
```
$ ../dynamorio/exports/bin64/drrun -c ./libshadowstack.so -- <program>
```
