#!/bin/bash

set -e

if [ "$(basename $(pwd))" != "api" ]; then
    echo "Error: you must run this from the docs/api directory" >&2
    exit 1
fi

destdir="$1"
shift

if [ -d "$destdir" ]; then
    rm -rf "$destdir"
fi

docsify init --local "$destdir"

rm -f "$destdir"/README.md

if [ -n "$NPM_PACKAGES" ]; then
    npm_dir="$NPM_PACKAGES/lib/node_modules"
elif [ -n "$NODE_PATH" ]; then
    npm_dir="$NODE_PATH"
elif [ -d "$HOME/node_modules" ]; then
    npm_dir="$HOME/node_modules"
elif [ -d "/usr/local/lib/node_modules" ]; then
    npm_dir="/usr/local/lib/node_modules"
else
    echo "Can't determine your node_modules path; set NPM_PACKAGES or NODE_PATH appropriately" >&2
    exit 1
fi

cp $npm_dir/docsify/node_modules/prismjs/components/prism-{json,python}.min.js "$destdir"/vendor

./api-to-markdown.py --out="$destdir" "$@"

perl -ni -e '
BEGIN { $first = 0; }
if (m{^\s*<script>\s*$} .. m{^\s*</script>\s*$}) {
    if (not $first) {
        $first = false;
        print qq{
  <script>
    window.\$docsify = {
      name: "Libsession Utils API",
      repo: "https://github.com/oxen-io/libsession-util",
      loadSidebar: "sidebar.md",
      subMaxLevel: 2,
      homepage: "index.md",
    }
  </script>\n};
    }
} else {
    s{<title>.*</title>}{<title>Libsession Utils API</title>};
    s{(name="description" content=)"[^"]*"}{$1"libsession-util function documentation"};
    if (m{^\s*</body>}) {
        print qq{
  <script src="vendor/prism-json.min.js"></script>
  <script src="vendor/prism-python.min.js"></script>\n};
    }
    print;
}' "$destdir"/index.html
