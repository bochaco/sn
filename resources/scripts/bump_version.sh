#!/usr/bin/env bash

commit_message=""
sn_version=""
sn_api_version=""
sn_cli_version=""
safe_network_has_changes=false
sn_api_has_changes=false
sn_cli_has_changes=false

function crate_has_changes() {
    local crate_name="$1"
    local output
    output=$(cargo smart-release \
        --update-crates-index \
        --no-push \
        --no-publish \
        --no-changelog-preview \
        --allow-fully-generated-changelogs \
        --no-changelog-github-release \
        "$crate_name" 2>&1)
    if [[ $output == *"WOULD auto-bump provided package '$crate_name'"* ]]; then
        echo "true"
    else
        echo "false"
    fi
}

function determine_which_crates_have_changes() {
    local has_changes
    has_changes=$(crate_has_changes "safe_network")
    if [[ $has_changes == "true" ]]; then
        echo "smart-release has determined safe_network crate has changes"
        safe_network_has_changes=true
    fi
    has_changes=$(crate_has_changes "sn_api")
    if [[ $has_changes == "true" ]]; then
        echo "smart-release has determined sn_api crate has changes"
        sn_api_has_changes=true
    fi
    has_changes=$(crate_has_changes "sn_cli")
    if [[ $has_changes == "true" ]]; then
        echo "smart-release has determined sn_cli crate has changes"
        sn_cli_has_changes=true
    fi
    if [[ $safe_network_has_changes == false ]] && \
       [[ $sn_api_has_changes == false ]] && \
       [[ $sn_cli_has_changes == false ]]; then
        echo "smart-release detected no changes in any crates. Exiting."
        exit 0
    fi
}

function generate_version_bump_commit() {
    local run_process=""
    run_process="cargo smart-release --update-crates-index --no-push --no-publish --no-changelog-preview --allow-fully-generated-changelogs --no-changelog-github-release --execute "
    if [[ $safe_network_has_changes == true ]]; then run_process="${run_process} safe_network "; fi
    if [[ $sn_api_has_changes == true ]]; then run_process="${run_process} sn_api "; fi
    if [[ $sn_cli_has_changes == true ]]; then run_process="${run_process} sn_cli "; fi
    echo "Will run smart-release with the following command: "
    echo "$run_process"
    eval $run_process
    exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo "smart-release did not run successfully. Exiting with failure code."
        exit 1
    fi
}

function generate_new_commit_message() {
    sn_version=$(grep "^version" < sn/Cargo.toml | head -n 1 | awk '{ print $3 }' | sed 's/\"//g')
    sn_api_version=$(grep "^version" < sn_api/Cargo.toml | head -n 1 | awk '{ print $3 }' | sed 's/\"//g')
    sn_cli_version=$(grep "^version" < sn_cli/Cargo.toml | head -n 1 | awk '{ print $3 }' | sed 's/\"//g')
    commit_message="chore(release): "

    if [[ $safe_network_has_changes == true ]]; then
        commit_message="${commit_message}safe_network-${sn_version}/"
    fi
    if [[ $sn_api_has_changes == true ]]; then
        commit_message="${commit_message}sn_api-${sn_api_version}/"
    fi
    if [[ $sn_cli_has_changes == true ]]; then
        commit_message="${commit_message}sn_cli-${sn_cli_version}/"
    fi
    commit_message=${commit_message::-1} # strip off any trailing '/'
    echo "generated commit message -- $commit_message"
}

function amend_version_bump_commit() {
    git reset --soft HEAD~1
    git add --all
    git commit -m "$commit_message"
}

function amend_tags() {
    if [[ $safe_network_has_changes == true ]]; then git tag "safe_network-v${sn_version}" -f; fi
    if [[ $sn_api_has_changes == true ]]; then git tag "sn_api-v${sn_api_version}" -f; fi
    if [[ $sn_cli_has_changes == true ]]; then git tag "sn_cli-v${sn_cli_version}" -f; fi
}

determine_which_crates_have_changes
generate_version_bump_commit
generate_new_commit_message
amend_version_bump_commit
amend_tags