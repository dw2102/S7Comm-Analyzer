# @TEST-EXEC: zeek -NN ICS::S7Comm |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
