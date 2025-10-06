build_pysrc()
{
    src_dir=$1
    dst_dir=$2
    module_name=$3
    module_ver=$(python -c "import sys, os; sys.path.append(r'$src_dir'); from $module_name import __version__ as v; print(v)")
    module_ver=$(echo $module_ver | sed -E 's/\./_/g')
    echo build ${module_name}_v${module_ver}.py
    cp -f $src_dir/${module_name}.py $dst_dir/${module_name}_v${module_ver}.py
}

build_csrc()
{
    src_dir=$1
    dst_dir=$2
    module_name=$3
    module_ver=$(awk '/.*_VERSION/ {print $3}' $src_dir/$module_name.h | sed 's/"//g')
    module_ver=$(echo $module_ver | sed -E 's/\./_/g')
    echo build ${module_name}_v${module_ver}.h
    cp -f $src_dir/${module_name}.h $dst_dir/${module_name}_v${module_ver}.h
}

mkdir -p build/src
build_csrc depend/winreverse/src build/src commdef
build_csrc src build/src winversion
build_csrc src build/src winoverride
cp -f src/winversion.def build/src/winversion.def