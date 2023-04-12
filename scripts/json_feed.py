from bs4 import BeautifulSoup

import glob
import json
import os

# retrieve the folder paths
currentPath = os.path.dirname(os.path.abspath(__file__))
docsPath = os.path.join(currentPath, '../docs/')

# global variable where we store the results
articles = []
videos = []

#
# Parses a HTML page and updates the `results` variable
#
def parseHTML(filePath):
  # open the file
  html = open(filePath, 'r', encoding='utf8')

  # retrieve the category
  category = os.path.basename(filePath).split('.')[0]

  # parse the file with BeautifulSoup
  soup = BeautifulSoup(html, 'html.parser')

  # retrieve all the <a> tags
  for link in soup.find_all('a'):
    href = link.get('href')
    title = link.get_text()

    # validation
    if not href or not title:
      continue

    # process articles
    if ('../articles' in href) or ('../newsletter' in href):
      # formatting
      if '#' in href:
        href = href.split('#')[0]
        href = href.replace('../', '/')

      # update the results
      updateResults(title, href, category, 'article')

    # process youtube videos
    if ('youtu.be' in href) or ('youtube.com' in href):
      updateResults(title, href, category, 'video')

#
#
#
def updateResults(title, href, category, _type):
  # search for duplicates
  if _type == 'article':
    duplicates = [item for item in articles if item.get('href') == href]
  else:
    duplicates = [item for item in videos if item.get('href') == href]

  # print a warning and skip
  if len(duplicates):
    print("[x] %s duplicate found for %s in category %s" % (_type, href, category))
    return

  # dealing with pesky unicode characters
  title = title.replace("\u2013", "-")
  title = title.replace("\u2018", "'")
  title = title.replace("\u2019", "'")

  # create object
  item = {
    'title': title,
    'href': href,
    'categories': [category]
  }

  # add the new link to the results
  if _type == 'article':
    articles.append(item)
  else:
    videos.append(item)

#
# Main function
#
def main ():
  # list of sub folders to process
  subFolders = [
    'cyber-domains',
    'it-domains',
    'tutorials'
  ]

  # iterate through the folders and process them
  for folder in subFolders:
    # retrieve the absolute path
    folder = os.path.join(docsPath, '_build/html', folder)
    folder = os.path.abspath(folder)

    # iterate through the html files
    for f in glob.glob("%s/*.html" % folder):
      # debug message
      print("[-] Processing: %s" % f)

      # parse the HTML and retrieve all the links
      parseHTML(f)

    # write articles to disk
    writeArticles()

    # write videos to disk
    writeVideos()

#
# Write all the articles in JSON format to disk
#
def writeArticles():
  # convert the articles to JSON
  json_string = json.dumps({
    'posts': articles
  }, sort_keys=True, indent = 2, separators = (',', ': '))
  
  # open the file where the results are stored
  outfile = os.path.join(docsPath, '_static/feed.json')
  outfile = os.path.abspath(outfile)
  outfile = open(outfile, 'w')

  # write the results to disk
  outfile.write(json_string)

  # debug message
  print("\n[v] Success! Wrote %d articles to feed.json" % len(articles))

#
# Write all the videos in JSON format to disk
#
def writeVideos():
  # convert the articles to JSON
  json_string = json.dumps({
    'posts': videos
  }, sort_keys=True, indent = 2, separators = (',', ': '))
  
  # open the file where the results are stored
  outfile = os.path.join(docsPath, '_static/videos.json')
  outfile = os.path.abspath(outfile)
  outfile = open(outfile, 'w')

  # write the results to disk
  outfile.write(json_string)

  # debug message
  print("\n[v] Success! Wrote %d videos to videos.json" % len(videos))

#
#
#
if __name__ == "__main__":
  main()