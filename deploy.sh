#!/bin/sh

# If a command fails then the deploy stops
set -e

printf "\033[0;32mDeploying updates to GitHub...\033[0m\n"

printf "\033[0;32m1. To vivescere/personal-website\033[0m\n"

msg="rebuilding site $(date)"
if [ -n "$*" ]; then
	msg="$*"
fi

# Build the project.
hugo --minify # if using a theme, replace with `hugo -t <YOURTHEME>`

git add .
git commit -m "$msg"
git push origin master

printf "\n\033[0;32m2. To vivescere.github.io\033[0m\n"

# Go To Public folder
cd public

# Add changes to git.
git add .

# Commit changes.
git commit -m "$msg"

# Push source and build repos.
git push origin master
