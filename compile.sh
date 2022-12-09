rm -rf ./build
cmake . -Bbuild -DCMAKE_BUILD_TYPE=release
#cmake . -Bbuild -DCMAKE_BUILD_TYPE=debug
make -C build
