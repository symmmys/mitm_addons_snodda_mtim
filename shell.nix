with import <nixpkgs> { }; 
let 
ps = python3Packages; 
in pkgs.mkShell rec { 
name = "all_addons"; 
venvDir = "./.venv";
buildInputs = [
# A Python interpreter including the 'venv' module is required to bootstrap the environment. 
ps.python
ps.pyperclip
#ps.scapy
# This execute some shell code to initialize a venv in $venvDir before
# dropping into the shell
ps.venvShellHook
ps.python-gitlab
ps.GitPython

# In this particular example, in order to compile any binary extensions they may
# require, the Python modules listed in the hypothetical requirements.txt need
# the following packages to be installed locally:
git
zip
];
#Run this command, only after creating the virtual environment
postVenvCreation = '' 
unset SOURCE_DATE_EPOCH 
'';
#Now we can execute any commands within the virtual environment.
#This is optional and can be left out to run pip manually.
postShellHook = '' 
# allow pip to install wheels 
unset SOURCE_DATE_EPOCH 
''; 
}
