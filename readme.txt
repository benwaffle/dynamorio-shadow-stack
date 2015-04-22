to build dynamorio:
    $ mkdir build && cd build 
    $ cmake .. && make && make install

to build shadow stack:
    $ mkdir build && cd build 
    $ cmake .. && make

to run shadow stack:
in build/
    $ ../dynamorio/exports/bin64/drrun -c ./libdemo.so -- <program>
