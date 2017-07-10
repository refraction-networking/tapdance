#!/bin/sh

sed -i 's/\/\/HACKY_CFG_NO_TEST_BEGIN/\/\*\/HACKY_CFG_NO_TEST_BEGIN/' src/*
sed -i 's/\/\*\/\/HACKY_CFG_YES_TEST_BEGIN/\/\/\/HACKY_CFG_YES_TEST_BEGIN/' src/*
cargo test
sed -i 's/\/\*\/HACKY_CFG_NO_TEST_BEGIN/\/\/HACKY_CFG_NO_TEST_BEGIN/' src/*
sed -i 's/\/\/\/HACKY_CFG_YES_TEST_BEGIN/\/\*\/\/HACKY_CFG_YES_TEST_BEGIN/' src/*
