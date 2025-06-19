#!/usr/bin/env bash

CL_FILE=$1
SPEC_FILE=$2
AUTHOR=$3

CHANGELOG=""

while IFS= read -r line; do
    if [[ "$line" =~ ^#.*([0-9]+\.[0-9]+\.[0-9]+).*\(([^\)]+)\) ]]; then
      v=${BASH_REMATCH[1]}
      d=${BASH_REMATCH[2]}
      df=$(date -d "$d" "+%a %b %d %Y" 2> /dev/null)

      if [[ -n "$CHANGELOG" ]]; then
        CHANGELOG+="\n"
      fi

      CHANGELOG+="* ${df:=$d} ${AUTHOR:=René Adler} - $v\n"
    elif [[ "$line" =~ ^\*([^\(]+) ]]; then
      CHANGELOG+="- ${BASH_REMATCH[1]}\n"
    fi
done < "$CL_FILE"

cp $SPEC_FILE "$SPEC_FILE.bak"
FP=$(sed -n '1,/%changelog/p' "$SPEC_FILE.bak")
echo -e "$FP\n$CHANGELOG" > $SPEC_FILE
rm -f "$SPEC_FILE.bak"
