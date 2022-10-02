from bs4 import BeautifulSoup
import os
import glob
import sys


ini= '{\n\t"title":'
end= '\n}'

# creating a feed for it domain
fpath = "/home/elka/Desktop/mcsi-library/docs/_build/html/it-domains/*.html" 
for files in sorted(glob.glob(fpath, recursive=True)):

    with open(files) as f:
        html_content = f.read()

        soup = BeautifulSoup(html_content, 'lxml')
        cat = soup.find("meta", property="og:title")['content']

        snippets = soup.select("section h3 span")

        if snippets:
            match = soup.select("section h3")
            for i in match:
                url = i.a['href'].split('#')[0][2:]
                title = i.span.text
                
                print(f'{ini}"{title}",\n\t"url": "{url}",\n\t"category": ["{cat}"]{end},')
        else:
            simple = soup.select("li p a")
            if simple:
                for i in simple:
                    url=i['href'][2:].split("#")[0]
                    title=i.span.text
                    print(f'{ini}"{title}",\n\t"url": "{url}",\n\t"category": ["{cat}"]{end},')


                   

