# Web cache poisoning

## Constructing a web cache poisoning attack

1. Identify and evaluate unkeyed inputs

- Adding random inputs to the request and detect reflection in the response.
- We can automate the process of identifying unkeyed inputs by Param Miner in burp. 
- Note: Don't forget to add cache buster in requests.

2. Elicit a harmful response from the back-end server
3. Get the response cached
    - Manipulating inputs to elicit a harmful response is half the battle, but it doesn't achieve much unless you can cause the response to be cached, which can sometimes be tricky.
    - You will probably need to devote some time to simply playing around with requests on different pages and studying how the cache behaves.Once you work out how to get a response cached that contains your malicious input, you are ready to deliver the exploit to potential victims.






## Resources

- Writeups
- https://www.sec-down.com/InterestingGooglevulnerability3137reward..html (X-HTTP-Method-Override:)
-   [chaining-cache-poisoning-to-stored-xss  ](https://nahoragg.medium.com/chaining-cache-poisoning-to-stored-xss-b910076bda4f)
-   [web-cache-poisoning-worth-it ](https://yaseenzubair.medium.com/web-cache-poisoning-worth-it-e7c6d88797b1) 
-   [sensitive-information-disclosure-web-cache...](https://medium.com/@dr.spitfire/sensitive-information-disclosure-web-cache-deception-attack-bcac6cb9cd86)  
- https://infosecwriteups.com/how-i-made-16-500-hacking-cdn-caching-servers-part-2-4995ece4c6e6
- https://book.hacktricks.xyz/pentesting-web/cache-deception
- https://youst.in/posts/cache-poisoning-at-scale/
- https://portswigger.net/research/practical-web-cache-poisoning
- Black Hat:    [• Web Cache Deception Attack  ](https://www.youtube.com/watch?v=mroq9eHFOIU&t=0s)
- Black Hat:    [• Practical Web Cache Poisoning ](https://www.youtube.com/watch?v=j2RrmNxJZ5c&t=0s) 
