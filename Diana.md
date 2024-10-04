![](assets/images/banner.png)



<img src="assets/images/cd.svg" style="margin-left: 20px; zoom: 60%;" align=left />    	<font size="10">Compromised</font>

​		16<sup>th</sup> Feb 2024

​		Challenge Author(s): Abdelrhman

​		

 



### Description:

Our SOC team detected a suspicious activity in Network Traffic ,the machine has been compromised and company information that should not have been on there has now been stolen – it’s up to you to figure out what has happened and what data has been taken.

### Objective

* Knowing about DANABOT c2 how it works 
* knowing about realscenario attack
* how to analyze traffic 
* how to analyze obfuscated javascript code
* how to analyze malicious file in sandbox
### Difficulty:

`Medium`

```js
[1] What is the IP address for attacker of initial access?

[2] what is the protocol that attacker exploit? 

[3] what is the file name that used for initial access?

[4] what is the sha256 hash of the file that used for initial access?

[5] what is the Run method used to run it

[6] what is the file extension that used for persistence

[7]what is the md5 hash of the file that used for persistence?

[8] what is the IP address for attacker of consistently used in persistence

[9] what is the name of Command & Control that attacker used? 



```



# Challenge
ok now first let's look for our traffic 

![traffic](/assets/images/traffic.png)

we saw that `62.173.146.41` send obfuscate javascript to our server `10.2.14.101` ok now let's put it in file and upload it to virusTotal to see it malicious or what

![javascript](/assets/images/javascript.png)

ok now we see that it's malicious so let's run it on [any.run](https://any.run/)
![any](/assets/images/any.png)

ok the run method it used is `wscript.exe` it dropped one file with 2 names and 2 paths we take md5 hash of each file they have same content with different names  ```md5: e758e07113016aca55d9eda2b0ffeebe```

now let's upload this md5 to virus total
![virustotal](/assets/images/virustotal.png)

ok we see that it's `Danabot c2`

ok now we need to find the ip address of attacker that is used to exfiltrate the data
we look for conversation

![wireshark](/assets/images/wireshark.png)
most 2 ips have packets with our server are `188.114.97.3` and `195.133.88.98` one of them is malicious so let's make some investigation about them

ok when we look about `195.133.88.98` on virus total we see that it's malicious
![maliciou_ip](/assets/images/maliciou_ip.png)
ok let's look for our traffic now 
`ip.addr==195.133.88.98`
we see encrypted traffic and that is our c2 so
`195.133.88.98` is used for persistence 
![encrypted](/assets/images/encrypted.png)
# Solver

## [1] What is the IP address for attacker of initial access?

Answer=> <mark> 62.173.146.41</mark>

## [2] what is the protocol that attacker exploit? 

Answer=> <mark> http</mark>

## [3] what is the file name that used for initial access?

Answer=> <mark>allegato_708.js</mark>

## [4] what is the sha256 hash of the file that used for initial access?

Answer=> <mark>847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268</mark>

## [5] what is the Run method used to run it

Answer=> <mark>wscript.exe</mark>


## [6] what is the file extension that used for persistence

Answer=> <mark> .dll</mark>


## [7]what is the md5 hash of the file that used for persistence?

Answer=> <mark>e758e07113016aca55d9eda2b0ffeebe</mark>

## [8] what is the name of Command & Control that attacker used? 

Answer=> <mark> Danabot C2</mark>

## [9] what is the IP address for attacker of consistently used in persistence

Answer=> <mark>195.133.88.98</mark>

