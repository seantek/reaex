#!/bin/sh

#  extract-abnf-from-rfcs2.sh
#  
#
#  Created by Sean on 9/20/16.
#
mkdir extracted-abnf

time (

let successabnf=0
let failureabnf=0

for f in $@
do
  filename=$(basename "$f")
  echo "Processing $filename"
  reaex.pl -t $f > "extracted-abnf/${filename%.*}.abnf" 2> "extracted-abnf/${filename%.*}.err"
  reaexexit="$?"
  if (("$reaexexit" > 0))
  then
    mv "extracted-abnf/${filename%.*}.err" "extracted-abnf/${filename%.*}.err.${reaexexit}"
    rm "extracted-abnf/${filename%.*}.abnf"
    ((failureabnf++))
  else
    rm "extracted-abnf/${filename%.*}.err"
    ((successabnf++))
  fi
done

# echo "RFCs processed: ABNF extracted = $successabnf; ABNF not extracted = $failureabnf"

if command -v say > /dev/null 2>&1; then
  say "RFCs processed: ABNF extracted = $successabnf; ABNF not extracted = $failureabnf" &
elif command -v espeak > /dev/null 2>&1; then
  espeak "RFCs processed: ABNF extracted = $successabnf; ABNF not extracted = $failureabnf" &
fi

echo "RFCs processed: ABNF extracted = $successabnf; ABNF not extracted = $failureabnf" > extracted-abnf/results.txt

) 2>> "extracted-abnf/results.txt"

cat extracted-abnf/results.txt

# echo "RFCs processed: ABNF extracted = $successabnf; ABNF not extracted = $failureabnf" $'\x0A' "$(cat extracted-abnf/results.txt)" > "extracted-abnf/results.txt"
