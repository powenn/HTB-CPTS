#

# CMS

## WordPress

To find plugin versions , ex : wp-sitemap-page  
`http://blog.inlanefreight.local/wp-content/plugins/wp-sitemap-page/readme.txt`

`curl http://blog.inlanefreight.local/?p=1 | grep plugin`  
`curl http://blog.inlanefreight.local | grep plugin`

**wpscan**

The tool uses two kinds of login brute force attacks, `xmlrpc` and `wp-login`.  
The `wp-login` method will attempt to brute force the standard WordPress login page, while the `xmlrpc` method uses WordPress API to make login attempts through /xmlrpc.php.  
***The `xmlrpc` method is preferred as it’s faster.***
