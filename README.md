# MCSI LIBRARY

![GitHub followers](https://img.shields.io/github/followers/mosse-security?style=social)![GitHub last commit](https://img.shields.io/github/last-commit/mosse-security/mcsi-library)

## What the project does

This project creates the MCSI LIBRARY using Sphinx and Read The Docs

## 🔨 How to set up the local development environment

To get started with this project follow these simple steps:

**Step-1** Change directory to a place where you want to store the code of this project.

**Step-2** Create a new directory:

`mkdir mcsi-blog`

`cd mcsi-blog`

**Step-3** Make sure git is installed:

`git --version`

If you don't have git dyou can download it running the following command:

`sudo apt install git`

**Step-4** Open a terminal and clone this repository with the following command:

`git clone https://github.com/mosse-security/mcsi-library.git`


Now you have a local copy of the repository.


## 🐱‍💻 Running the project on localhost


**Step-1** Open VS Code.

**Step-2** Click on File on the left hand menu and click on open folder. You can also press CTRL+K and CTRL+O.

**Step-3** Open the local copy of the mcsi-blog project folder you cloned in the previous step.

**Step-4** Open a new terminal in the VS Code and make sure you are in the mcsi-blog folder.

**Step-5** Activate the environment with the following command:

`source env8/bin/activate`

**Step-6** Change directory to the docs folder and run the following commands:

`make clean html`

When the build succeeds, the HTML pages will be in _build/html. 

**Step-7** We will use sphinx-autobuild to run this project on our localhost by running the following command:

`sphinx-autobuild . _build/`

The output will be similar to this:

```
The HTML pages are in _build/html.
[I 220824 06:18:10 server:335] Serving on http://127.0.0.1:8000
[I 220824 06:18:10 handlers:62] Start watching changes
```

**Step-8** Copy and paste the address on your browser.

Now you have run this repository on your localhost.

## 🖥️ Running the site on Windows

```
pip install sphinx
pip install sphinx-autobuild
cd docs/
pip install -r requirements.txt
sphinx-autobuild . _build/html
```

## How to deploy your project to Read the Docs


* Sign up to read the docs: https://readthedocs.org/.

* Click on your username on the upper right hand of the menu.

* Click on import a project.

* Click on the project you want to deploy from the list.

* Leave the settings at default and click on next.

* You can track the build on Builds section on the *Admin* page.

* Once the build is complete, you can view by clicking on the *View Docs* section.

## 🏗️ Enabling single version

* Go to the advanced settings on the admin page.

* Click on single version and save. 

You will see that the `/version/en/` is removed from the url by enabling single version.

<br>

## 🖼️ How to Create Open Graph Images for your Articles using Canva

### What is open graph image?

Open graph images are those that are used on social media platforms to represent a piece of content. They are usually rectangular in shape and have a specific size. The most common size for open graph images is 1200x630 pixels. These images are usually placed at the top of a web page or blog post, and they help to give users a preview of what the content is about. When users share links to content on social media, the open graph image is usually the first thing that people see. This makes it important for businesses and individuals to choose open graph images that are attention-grabbing and relevant to the content that they are sharing.

## 📷 How I can create open graph images?

In the video below, you're going to learn how you can create open graph images for your articles. 




https://user-images.githubusercontent.com/96833570/191314417-8067151e-8a81-42b5-9914-834f48ce3834.mp4




