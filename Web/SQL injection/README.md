# SQL injectin









## Automated Tools and various techniques to discover SQL injection

`$ echo "http://<target>/" | gau | uro | grep "\?" | sed "s/=.*/=A\'/" | uniq > params.txt; cat params.txt | httpx -mr ".*SQL.*|.*syntax.*|.*error.*"`