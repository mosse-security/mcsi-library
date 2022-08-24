# MCSI BLOG 



## What the project does

This project creates the MCSI blog page using Sphinx and Read The Docs

## How to set up the local development environment

To get started with this project follow these simple steps:

Change directory to a place where you want to store the code of this project.

Create a new directory:

`mkdir mcsi-blog`
`cd mcsi-blog`

Make sure git is installed

`git --version`

If you don't have git dyou can download it running the following command:

`sudo apt install git`

Open a terminal and clone this repository with the following command:

`git clone https://github.com/mosse-security/mcsi-library.git`


Now you have a local copy of the repository.


## Running the project on localhost


Open VS Code.

Click on File on the left hand menu and click on open folder. You can also press CTRL+K and CTRL+O.
Open the local copy of the mcsi-blog project folder you cloned in the previous step.

Open a new terminal in the VS Code and make sure you are in the mcsi-blog folder.

Activate the environment with the following command:

`source env8/bin/activate`

Change directory to the docs folder and run the following commands:

`make clean html`






## Who maintains and contributes to the project