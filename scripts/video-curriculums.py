from bs4 import BeautifulSoup

import glob
import json
import os

# retrieve the folder paths
currentPath = os.path.dirname(os.path.abspath(__file__))
docsPath = os.path.join(currentPath, '../docs/')

# global variable where we store the results
courses = []

#
#
#
def normalizeURL(url):
  key = url.split('/')[-1]
  key = key.replace('watch?v=', '')

  return 'https://www.youtube.com/embed/' + key

#
#
#
def parseHTML(filePath):
  # store retrieved course sections
  sections = []

  # open the file
  html = open(filePath, 'r', encoding='utf8')
  content = html.read()

  # validation
  if not '#free-video-course' in content:
    return

  # retrieve the category
  category = os.path.basename(filePath).split('.')[0]

  # debug message
  print("[-] Processing: %s" % category)

  # parse the file with BeautifulSoup
  soup = BeautifulSoup(content, 'html.parser')

  # retrieve the course
  course = soup.find('section', {'id': 'free-video-course'})
  
  # iterate through the sections
  for section in course.find_all('section'):
    # retrieve the module title
    section_title = section.find('h3').get_text().replace('#', '')
    
    # retrieve the videos
    videos = []

    for link in section.find_all('a'):
      href = link.get('href')
      video = link.get_text()

      # validation
      if not href or not video:
        continue
      
      # dealing with pesky unicode characters
      video = video.replace("\u2013", "-")
      video = video.replace("\u2018", "'")
      video = video.replace("\u2019", "'")
      
      # validation
      if ('youtu.be' in href) or ('youtube.com' in href):
        href = normalizeURL(href)

        videos.append({
          'title': video,
          'url': href
        })

    # save the section
    sections.append({
      'module': section_title,
      'videos': videos
    })

  # save the results
  courses.append({
    'category': category,
    'modules': sections
  })

#
# Write the output to disk
#
def writeVideos():
    # convert the articles to JSON
  json_string = json.dumps({
    'courses': courses
  }, sort_keys=True, indent = 2, separators = (',', ': '))
  
  # open the file where the results are stored
  outfile = os.path.join(docsPath, '_static/video-courses.json')
  outfile = os.path.abspath(outfile)
  outfile = open(outfile, 'w')

  # write the results to disk
  outfile.write(json_string)

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
      # parse the HTML and retrieve all the links
      parseHTML(f)

  # save the final results
  writeVideos()

#
#
#
if __name__ == "__main__":
  main()