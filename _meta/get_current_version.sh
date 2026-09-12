version=$(date -d "$(git show -s --format=%cI --date=iso-strict HEAD)" -u +"%Y-%m-%d_%H-%M-%SZ")__$(git rev-parse HEAD)
echo "Version: v"$version

