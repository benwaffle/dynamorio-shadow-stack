to build dynamorio:
    $ mkdir build && cd build 
    $ cmake .. && make && make install

to build shadow stack:
    same thing without `make install`

to run shadow stack:
in build/
    $ ../dynamorio/exports/bin64/drrun -c ./libdemo.so -- <program>
