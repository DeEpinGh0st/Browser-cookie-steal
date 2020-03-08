from chrome_cookie import ChromeCookieJar

if __name__=='__main__':
    jar = ChromeCookieJar()
    jar.load()
    for cookie in jar:
        print(vars(cookie))
