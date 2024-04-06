#!/bin/bash

#   This file is part of GNU libmicrohttpd
#   Copyright (C) 2024 Karlson2k (Evgeny Grin), Christian Grothoff

#   This library is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.

#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.

#   You should have received a copy of the GNU Lesser General Public
#   License along with this library; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA  02110-1301  USA


export LC_ALL=C
export LANG=C

if command -v recsel >/dev/null 2>&1 ; then : ; else
  echo "Error: The command 'recsel' is missing. Please install recutils." >&2
  exit 1
fi

if command -v recset >/dev/null 2>&1 ; then : ; else
  echo "Error: The command 'recset' is missing. Please install recutils." >&2
  exit 1
fi

if command -v recfmt >/dev/null 2>&1 ; then : ; else
  echo "Error: The command 'recfmt' is missing. Please install recutils." >&2
  exit 1
fi

if (( 0 + 1 )) 2>/dev/null && test "$(( 2 + 2 ))" = "4" 2>/dev/null ; then : ; else
  echo "Error: Built-in shell math is required" >&2
  exit 1
fi

if declare -a ARGS 2>/dev/null ; then : ; else
  echo "Error: Indexed arrays support is required" >&2
  exit 1
fi

if [[ "false" ]] ; then : ; else
  echo "Error: Compound command support is required" >&2
  exit 1
fi

if [[ $'\n' = '
' ]] ; then : ; else
  echo "Error: ANSI-C quoting support is required" >&2
  exit 1
fi

if [[ "abc" =~ 'b' ]] && [[ "xyz" =~ [x-z]{3} ]] ; then : ; else
  echo "Error: Regular expression match support is required" >&2
  exit 1
fi

test_var="abc ABC Abc"
if test "${test_var^}" = "Abc ABC Abc" && test "${test_var^^}" = "ABC ABC ABC" && test "${test_var,,}" = "abc abc abc"; then : ; else
  echo "Error: Shell upper- and lowercase variable conversion support required" >&2
  exit 1
fi

if test "${test_var// /_}" = "abc_ABC_Abc" ; then : ; else
  echo "Error: Shell variable replacement conversion support required" >&2
  exit 1
fi

unset test_var

# parameters
max_width=79
input_rec="d_options.rec"
tmp_rec_name="D_Options_preproc"
tmp_rec_file="d_options_preproc.rec"

# fixed strings
flat_arg_descr='the value of the parameter'

err_exit() {
    local msg="$1"
    local err=$2
    
    [[ -z $msg ]] && msg="Error!"
    ( [[ -z $err ]] || (( err < 1 )) ) && err=2
    echo "$msg" >&1
    exit $err
}

# cut string an newline character
cut_str_nl() {
    local str="$1"
    declare -g cut_str_nl_res=''
    if [[ "$str" =~ $'\n' ]]; then
        cut_str_nl_res="${str%%$'\n'*}"
        return 0
    fi
    return 1
}

# cut string to given length at word boundary if possible
# process embedded new line characters
cut_str_word () {
    local str="$1"
    local len=$2
    declare -g cut_str_word_res=''
    [[ $len -le 0 ]] && return 1
    if cut_str_nl "${str:0:$(( len + 1 ))}"; then
        cut_str_word_res="${cut_str_nl_res}"
        return 0
    fi
    if [[ ${#str} -le $len ]]; then
        cut_str_word_res="${str}"
        return 0
    fi
    if [[ "${str:${len}:1}" = " " ]]; then
        cut_str_word_res="${str:0:${len}}"
        return 0
    fi
    cut_str_word_res="${str:0:${len}}"
    cut_str_word_res="${cut_str_word_res% *}"
    return 0
}

format_doxy() {
    local prefix1="$1" # first line prefix
    local desc="$2"
    local prefix2="$3" # prefix on all other lines
    local width="$4"
    local tmp_str
    declare -g format_doxy_res=''
    [[ -z $width ]] && width=$max_width
    prefix1="${prefix1%"${prefix1##*[! ]}"} " # force single trailing space
    [[ -z $prefix2 ]] && prefix2="$prefix1"
    [[ ${#prefix1} -ge $width ]] && err_exit "Too long prefix ('${prefix1}') for width $width."
    desc="${desc#"${desc%%[! ]*}"}"
    desc="${desc%"${desc##*[! ]}"}" # trim desc
    local width_r=$(( width - ${#prefix1} ))
    local tmp_str="${prefix1//?/ }" # Space-only string with the same length
    prefix2="
${prefix2}${tmp_str:${#prefix2}}"
    cut_str_word "$desc" $width_r || return 1
    format_doxy_res="${prefix1}${cut_str_word_res}"
    desc="${desc:${#cut_str_word_res}}"
    desc="${desc#"${desc%%[! ]*}"}" # trim leading spaces
    desc="${desc#$'\n'}" # remove leading newline character
    while [[ -n "$desc" ]]; do
        cut_str_word "$desc" $width_r || return 1
        format_doxy_res+="${prefix2}${cut_str_word_res}"
        desc="${desc:${#cut_str_word_res}}"
        desc="${desc#"${desc%%[! ]*}"}" # trim leading spaces
        desc="${desc#$'\n'}" # remove leading newline character
    done
    return 0
}

def_name_for_type() {
    case $1 in
        'enum MHD_Bool') echo -n "bool_val";;
        'unsigned int') echo -n "uint_val";;
        'uint_fast64_t') echo -n "uint64_val";;
        'uint_fast32_t') echo -n "uint32_val";;
        'uint_fast16_t') echo -n "uint16_val";;
        'size_t') echo -n "sizet_val";;
        *) local tp="${1,,}" && printf '%s' "${tp// /_}_val";;
    esac
}

capitalise_first() {
    local first_char="${1:0:1}"
    printf '%s' "${first_char^^}${1:1}"
}

recfix --check "$input_rec" || exit 3

cat << _EOF_ > "$tmp_rec_file"
%rec: ${tmp_rec_name}
%key: EName
%mandatory: Value
%mandatory: Name
%type: Value int
%sort: Value
%singular: EName UName Value

_EOF_

echo "Processing input file..."
for N in $(recsel -t MHD_Option -R Value "$input_rec")
do
    NAME=$(recsel -t MHD_Option -P Name -e "Value = $N" "$input_rec")
    if [[ -z $NAME ]]; then
      echo "The 'Name' field is empty for 'Value=$N'" >&2
      exit 2
    fi
    COMMENT=$(recsel -t MHD_Option -P Comment -e "Value = $N" "$input_rec")
    if [[ -z $COMMENT ]]; then
      echo "The 'Comment' field is empty for '$NAME' ('Value=$N')" >&2
      exit 2
    fi
    TYPE=$(recsel -t MHD_Option -P Type -e "Value = $N" "$input_rec")
    EComment="" # The initial part of doxy comment for the enum value
    EName=""    # The name of the enum value
    UName=""    # The name of the union member
    UType=""    # The type of the union member
    SComment="" # The doxy comment for the set macro/function
    SName=""    # The name of the set macro/function
    MArguments=""   # The arguments for the macro
    CLBody=""   # The Compound Literal body (for the set macro)
    SFArguments=""  # The arguments for the static function
    SFBody=""   # The static function body
    StBody=''   # The data struct body (if any)
    
    nested='maybe'  # The option has nested struct parameters ('yes'/'no'/'maybe')

    clean_name="${NAME//_/ }"
    clean_name="${clean_name,,}" # Lowercase space-delimited

    echo "$N: ${clean_name// /_}"

    EName="${clean_name^^}"
    EName="MHD_D_O_${EName// /_}" # Uppercase '_'-joined
    
    UName="v_${clean_name// /_}" # lowercase '_'-joined
    
    SName="${clean_name^^}"
    SName="MHD_DAEMON_OPTION_${SName// /_}" # Uppercase '_'-joined
    
    format_doxy '   * ' "$COMMENT" || err_exit
    EComment="$format_doxy_res"
    
    format_doxy ' * ' "$COMMENT" || err_exit
    SComment="$format_doxy_res"
    
    # Read option parameters
    ARGS=( )
    DESCRS=( )
    MEMBERS=( )
    M=1
    while
        ARGM=$(recsel -t MHD_Option -P Argument${M} -e "Value = $N" "$input_rec")
        [[ -n $ARGM ]]
    do
        ARGS[$M]="$ARGM"
        DESCRS[$M]="$(recsel -t MHD_Option -P Description${M} -e "Value = $N" "$input_rec")"
        MEMBERS[$M]="$(recsel -t MHD_Option -P Member${M} -e "Value = $N" "$input_rec")"
        (( M++ ))
    done
    
    # Basic data checks
    (( M - 1 == ${#ARGS[@]} )) || err_exit
    
    if [[ ${#ARGS[@]} -eq 0 ]]; then
        [[ -z $TYPE ]] && err_exit "No 'Argument1' is specified for '$NAME' ('Value=$N') without 'Type'" >&2
        nested='no'
        ARGS[1]=''
        DESCRS[1]="$flat_arg_descr"
        MEMBERS[1]=''
    elif [[ ${#ARGS[@]} -eq 1 ]]; then
        nested='no'
    else
        nested='yes'
        [[ -z $TYPE ]] && err_exit "No 'Type' is specified for non-flat (nested, with multiple parameters) '$NAME' ('Value=$N')" >&2
    fi
    
    # Process option parameters
    for (( M=1 ; M <= ${#ARGS[@]} ; M++ )) ; do
        
        arg_name='' # The name of the current argument
        arg_type='' # The type of the data of the current argument
        arg_descr='' # The description of the current argument
        nest_member='' # The name of the member of the nested structure
        [[ "${ARGS[$M]}" =~ (^' '|' '$) ]] && err_exit "'Argument${M}' value '${ARGS[$M]}' for '$NAME' ('Value=$N') is not trimmed"
        [[ "${DESCRS[$M]}" =~ (^' '|' '$) ]] && err_exit "'Description${M}' value '${DESCRS[$M]}' for '$NAME' ('Value=$N') is not trimmed"
        [[ "${MEMBERS[$M]}" =~ (^' '|' '$) ]] && err_exit "'Member${M}' value '${MEMBERS[$M]}' for '$NAME' ('Value=$N') is not trimmed"
        # Pre-process parameters data
        if [[ -n ${ARGS[$M]} ]]; then
            arg_name="${ARGS[$M]##* }"
            arg_name="${arg_name#\*}"
            arg_type="${ARGS[$M]%${arg_name}}"
            arg_type="${arg_type% }"
        else
            if [[ $nested = 'yes' ]]; then
                err_exit "Empty or no 'Argument${M}' ('$arg_type') for '$NAME' ('Value=$N')"
            else
                [[ -z $TYPE ]] && err_exit "No 'Argument1' is specified for '$NAME' ('Value=$N') without 'Type'" >&2
                arg_name="$(def_name_for_type "$TYPE")"
                arg_type="$TYPE"
            fi
        fi
        arg_descr="${DESCRS[$M]}"
        nest_membr="${MEMBERS[$M]}"

        [[ -z $arg_name ]] && err_exit # Should not happen
        if [[ $nested = 'yes' ]]; then
            # non-flat, nested
            [[ -z $arg_type ]] && err_exit "No argument type in 'Argument${M}' ('${ARGS[$M]}') for $NAME ('Value=$N')"
            [[ $TYPE = $arg_type ]] && \
                err_exit "The same 'Type' and type for in 'Argument${M}' ('$arg_type') used for non-flat (nested) '$NAME' ('Value=$N')"
            [[ -z $arg_descr ]] && \
                err_exit "Empty or no 'Description${M}' for argument '${ARGS[$M]}' for non-flat (nested) '$NAME' ('Value=$N')"
            if [[ "$arg_name" = "$nest_membr" ]]; then
                echo "The name for 'Argument${M}' ('${ARGS[$M]}') is the same as the 'Member${M}' ('$nest_membr') for non-flat (nested) '$NAME' ('Value=$N')" >&2
                nest_membr="v_${nest_membr}"
                echo "Auto-correcting the struct member name to '$nest_membr' to avoid wrong macro expansion" >&2
            fi
        else
            # flat, non-nested
            if [[ -z $arg_type ]]; then
                if [[ -z $TYPE ]]; then
                    err_exit "Both 'Type' and type for in 'Argument${M}' ('${ARGS[$M]}') are empty for '$NAME' ('Value=$N')"
                else
                    arg_type="$TYPE"
                fi
            else
                if [[ -z $TYPE ]]; then
                    TYPE="$arg_type"
                elif [[ $TYPE != $arg_type ]]; then
                    err_exit "Different 'Type' ('$TYPE') and type for in 'Argument${M}' ('$arg_type') used for '$NAME' ('Value=$N')"
                fi
            fi
            [[ -z $arg_descr ]] && arg_descr="$flat_arg_descr"
            [[ -n $nest_membr ]] && \
                err_exit "'Member${M}' is provided for non-nested (flat) '$NAME' ('Value=$N')"
        fi
        
        [[ "$arg_type" =~ \*$ ]] || arg_type+=' ' # Position '*' correctly
        [[ "$arg_name" = "${UName}" ]] && err_exit "The name ('$arg_name') of the argument 'Argument${M}' ('${ARGS[$M]}') for '$NAME' ('Value=$N') conflicts with the union member name ('${UName}'). Macro would not work."
        [[ "$arg_name" = "opt" ]] && err_exit "The name ('$arg_name') of the argument 'Argument${M}' ('${ARGS[$M]}') for '$NAME' ('Value=$N') conflicts with the option struct member name ('opt'). Macro would not work."
        [[ "$arg_name" = "val" ]] && err_exit "The name ('$arg_name') of the argument 'Argument${M}' ('${ARGS[$M]}') for '$NAME' ('Value=$N') conflicts with the option struct member name ('val'). Macro would not work."
        [[ "${arg_name,,}" = "${arg_name}" ]] || err_exit "The name ('$arg_name') of the argument 'Argument${M}' ('${ARGS[$M]}') for '$NAME' ('Value=$N') has capital letter(s)"
        [[ $nested = 'yes' ]] && [[ -z $nest_membr ]] && nest_membr="v_${arg_name}"
        [[ "${#arg_name}" -ge 15 ]] && echo "Warning: too long (${#arg_name} chars) parameter name '${arg_name}'." >&2
        
        [[ $M -gt 1 ]] && [[ $nested = 'no' ]] && err_exit
        
        # Use parameters data
        
        format_doxy ' * @param '"$arg_name " "$arg_descr" ' * '|| err_exit
        SComment+=$'\n'"$format_doxy_res"
        
        [[ $M -gt 1 ]] && MArguments+=','
        MArguments+="$arg_name"
        
        if [[ $nested = 'yes' ]]; then
            [[ $M -gt 1 ]] && SFArguments+=','
            SFArguments+=$'\n'"  ${arg_type}$arg_name"
        else
            SFArguments+="${arg_type}$arg_name"
        fi
        
        #[[ $M -gt 1 ]] && CLBody+=', \'$'\n'"    "
        [[ $M -gt 1 ]] && CLBody+=', \##removeme##'$'\n'"      " # '##removeme##' is a workaround for requtils bug
        CLBody+=".val.${UName}"
        [[ $nested = 'yes' ]] && CLBody+=".${nest_membr}"
        CLBody+=" = ($arg_name)"

        [[ $M -gt 1 ]] && SFBody+=$'\n'"  "
        SFBody+="opt_val.val.${UName}"
        [[ $nested = 'yes' ]] && SFBody+=".${nest_membr}"
        SFBody+=" = ${arg_name};"
        
        if [[ $nested = 'yes' ]] && [[ "$TYPE" =~ ^'struct ' ]]; then
            StBody+=$'\n'
            StBody+="  /**"$'\n'
            format_doxy '   * ' "$(capitalise_first "$arg_descr")" || err_exit
            StBody+="$format_doxy_res"$'\n'"   */"$'\n'
            StBody+="    ${arg_type}$nest_membr;"
        fi
    done
    
    UType="$TYPE"
    if [[ $nested = 'yes' ]] && [[ "$TYPE" =~ ^'struct ' ]]; then
        need_struct_decl='yes'
    else
        need_struct_decl='no'
    fi
    
    recins -t "${tmp_rec_name}" \
        -f Name -v "$NAME" \
        -f Value -v "$N" \
        -f EComment -v "$EComment" \
        -f EName -v "$EName" \
        -f UName -v "$UName" \
        -f UType -v "$UType" \
        -f SComment -v "$SComment" \
        -f SName -v "$SName" \
        -f MArguments -v "$MArguments" \
        -f CLBody -v "$CLBody" \
        -f SFArguments -v "$SFArguments" \
        -f SFBody -v "$SFBody" \
        -f StBody -v "$StBody" \
        --verbose "$tmp_rec_file" || err_exit
done
echo "finished."

echo "Generating output files..."
echo "enum..."
recfmt -f d_options_enum.template < "$tmp_rec_file" > enum_insert.h
echo "structs..."
recsel -e "StBody != ''" "$tmp_rec_file" | recfmt -f d_options_struct.template > struct_insert.h
echo "union..."
recfmt -f d_options_union.template < "$tmp_rec_file" > union_insert.h
echo "macros..."
recfmt -f d_options_macro.template < "$tmp_rec_file" | ${SED-sed} -e 's/##removeme##//g' - > macro_insert.h
echo "functions..."
recfmt -f d_options_func.template < "$tmp_rec_file" > func_insert.h
# rm "$tmp_rec_file"
echo "finished."
