#!/bin/bash
LICENSE=$(cat LICENSE)
IDENTIFIER="This script ensures source code files have copyright license headers. See license.sh for more information."
AUTHOR="Manifold Finance, Inc."
YEAR=$(date +%Y)

if [ $# -lt 1 ] || [ $# -gt 2 ] || [ "$2" != "update" -a "$#" -eq 2 ]; then
    echo "Usage: $0 path/to/directory [update]"
    exit 1
fi

DIR=$1

find "$DIR" \( -name "*.go" -o -name "*.js" -o -name "*.yaml" -o -name "*.html" -o -name "*.mustache" \) -type f | while read FILE; do
    if grep -q "$IDENTIFIER" "$FILE"; then
        if [[ "$2" == "update" ]]; then
            echo "Updating license header in $FILE"
            # Remove existing license header, including identifier
            END=$(grep -n "$IDENTIFIER" "$FILE" | cut -d ":" -f 1)
            sed -i "1,$END d" "$FILE"
        else
            echo "License header already present in $FILE"
            continue
        fi
    fi

    echo "Adding license header to $FILE"
    case "$FILE" in
        *.go) COMMENT="//" ;;
        *.js) COMMENT="//" ;;
        *.yaml) COMMENT="#" ;;
        *.html) COMMENT="<!--" ;;
        *.mustache) COMMENT="<!--" ;;
        *) COMMENT="//" ;;
    esac

    if [ "$COMMENT" == "<!--" ]; then
        echo -e "$LICENSE\n$IDENTIFIER" | sed "s|{{year}}|$YEAR|g" | sed "s|{{holder}}|$AUTHOR|g" | sed '/^[[:space:]]*$/d' | sed 's|^|'"$COMMENT"' |' | sed 's|$| -->|' | cat - "$FILE" > temp && mv temp "$FILE"
    else
        echo -e "$LICENSE\n$IDENTIFIER" | sed "s|{{year}}|$YEAR|g" | sed "s|{{holder}}|$AUTHOR|g" | sed '/^[[:space:]]*$/d' | sed '/./s|^|'"$COMMENT"' |' | cat - "$FILE" > temp && mv temp "$FILE"
    fi
done