#!/usr/bin/env /bin/bash

TEMPFILE="$(mktemp).jpg"
TEMPFILE_ICM="$(mktemp).icm"
trap "{ rm -f $TEMPFILE $TEMPFILE_ICM; }" EXIT

ALLOWED_EXT=("jpg" "JPG" "jpeg" "JPEG" "png" "PNG" "CR2")

function check_valid_ext {
    match=0

    for ext in "${ALLOWED_EXT[@]}"; do
        if [[ $ext = "$1" ]]; then
            match=1
            break
        fi
    done

    if [[ $match = 0 ]]; then
        echo "Invalid extension: $1"
        exit 1
    fi
}

function check_does_not_already_exist {
    if [[ -f "static/assets/$1" ]]; then
        echo "File already exists in static/assets/$1"
        exit 1
    fi
    if [[ -f "static/assets/minified/$1" ]]; then
        echo "File already exists in static/assets/minified/$1"
        exit 1
    fi
}

function process {
    convert -auto-orient -resize 1280x "$1" pnm:- | /usr/local/Cellar/mozjpeg/3.3.1_1/bin/cjpeg -quality 70 > "static/assets/minified/$2"
    cp "$1" "static/assets/$2"
}

function strip_exif {
    convert "$1" "$TEMPFILE_ICM"
    convert "$1" -auto-orient -strip -profile "$TEMPFILE_ICM" "$TEMPFILE"
    mv "$TEMPFILE" "$1"
    xattr -c "$1"
}

LINES=()

for path in "$@"
do
    filename=$(basename "$path")
    extension="${filename##*.}"

    echo "-> $filename"

    check_valid_ext "$extension"

    if [ "$extension" == "CR2" ] || [ "$extension" == "cr2" ]; then
        filename="$(basename "$filename" ".$extension").jpg"
        #convert "cr2:$path" "$TEMPFILE"
        sips -s format jpeg "$path" --out "$TEMPFILE"
        path="$TEMPFILE"
    fi

    LINES+=("[![](/assets/minified/$filename)](/assets/$filename)")
    
    check_does_not_already_exist "$filename"

    process "$path" "$filename"

    strip_exif "static/assets/$filename"
    strip_exif "static/assets/minified/$filename"

    du -h "static/assets/$filename"
    du -h "static/assets/minified/$filename"
done

echo "---"

printf '%s\n' "${LINES[@]}"
