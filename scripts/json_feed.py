from bs4 import BeautifulSoup

import glob
import json
import os

# retrieve the folder paths
currentPath = os.path.dirname(os.path.abspath(__file__))
docsPath = os.path.join(currentPath, '../docs/')

# global variable where we store the results
items = []

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

    # validation
    if not '../articles' in href:
      continue

    # formatting
    if '#' in href:
      href = href.split('#')[0]
      href = href.replace('../', '/')

    # update the results
    updateResults(title, href, category)

#
#
#
def updateResults(title, href, category):
  # search for duplicates
  duplicates = [item for item in items if item.get('href') == href]

  # print a warning and skip
  if len(duplicates):
    print("[x] duplicate found for %s in category %s" % (href, category))
    return

  # add the new link to the results
  items.append({
    'title': title,
    'href': href,
    'categories': [category]
  })

#
# Main function
#
def main ():
  # list of sub folders to process
  subFolders = [
    'cyber-domains',
    'it-domains'
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

    # convert the items to JSON
    json_string = json.dumps({
      'posts': items
    }, sort_keys=True, indent = 2, separators = (',', ': '))
    
    # open the file where the results are stored
    outfile = os.path.join(docsPath, '_static/feed.json')
    outfile = os.path.abspath(outfile)
    outfile = open(outfile, 'w')

    # write the results to disk
    outfile.write(json_string)

#
#
#
if __name__ == "__main__":
  main()