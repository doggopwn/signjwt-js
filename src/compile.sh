#!/usr/bin/env zsh
# ARGS = [debug, script_name, exported_functions, exec_args]
BLUE='\033[0;34m'
NC='\O33[0m'

# Load Emscripten
if ! command -v emcc 2>&1 >/dev/null
then
    source $HOME/emsdk/emsdk_env.sh 2>/dev/null
fi

DEBUG=$1;
exported_funcs='_ossl_fakerand_provider_init,_malloc,_free';
optimizer_flags='';
shift 1;

# Save script_name and .js file from script_name
INPUT=$1
OUTPUT=$(echo -n $1 | rev | cut -d"." -f2- | rev).js 
shift 1;
# Save exported funcs
exported_funcs="$exported_funcs,$(echo $1 | awk -e '{$0=gensub(/(^|,)([^_][^,]*)/, "\\1_\\2", "g")}1')"
shift 1;

if test "$DEBUG" = "debug"
then
	exported_funcs="_ENABLE_DEBUG,$exported_funcs";
	optimizer_flags=(-sEXCEPTION_CATCHING_ALLOWED=$exported_funcs -O0);
elif test "$DEBUG" = "nodebug"
then
	optimizer_flags="-O0"
elif test "$DEBUG" = "release"
then
	optimizer_flags=(-Oz -fno-rtti --closure=1 -sELIMINATE_DUPLICATE_FUNCTIONS=1) 
fi

# Set xtrace color to blue
PS4='%F{blue}'$SHELL'>%f'

# Compile
succ=$(set -o xtrace;\
emcc -Wall $optimizer_flags -sMODULARIZE=1 -sWASM=0 -sALLOW_MEMORY_GROWTH=1 -sENVIRONMENT=shell,node -sEXPORTED_FUNCTIONS=$exported_funcs -sEXPORTED_RUNTIME_METHODS=setValue,getValue,writeArrayToMemory,stringToUTF8,UTF8ToString -I$HOME/openssl/include -I$HOME/openssl/providers/implementations/include -L$HOME/openssl -lcrypto -lssl $INPUT -o $OUTPUT)

# Import the functions in Node.JS immediately

if ((succ? != 0)); then
	exit 1;
fi

CONTINUE=$(read -nq "Launch a Node.JS repl with the exported functions available? (y/n): ")

if test "$CONTINUE" = "n" 
then 
	exit 0;
fi

echo;
(set -o xtrace;\
	node ./importSSL.js $exported_funcs $@
	#node ./signJWT.js $exported_funcs $@
)

