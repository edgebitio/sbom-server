# SBOM Server #

## Development ##

This project makes use of git commit hooks. Configure git to use them by running
the following from the root of the repository:

    git config --local core.hooksPath .githooks

In an effort to increase the utility of the commit log, please include any
background information and reasoning in the commit message (i.e. the "why"
behind a change). Discussion will happen on GitHub, but don't assume future
developers will go back and read all of that history online. Make sure your
commit message adheres to the following format:

    <scope>: <title>
    
    <description>

The commit title (`<scope>` plus `<title>`) should be less than 50 characters
and the description should be wrapped at 70 characters. Please see the commit
log for a collection of examples.
