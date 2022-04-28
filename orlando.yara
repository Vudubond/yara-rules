rule MAL_BrownFlood_1
{
 meta:
  description = "To detect BrownFlood JavaScript DDoS implant"
  author = "CERT-UA"
  created = "2022-04-27"
  version = 2

 strings:
  $s1 = "://"
  $s2 = " fetch("

  $f1 = "AbortController()"
  $f2 = "Math.random()"
  $f3 = "await "
  $f4 = ".shift("
  $f5 = ".push("

  $m1 = "GET"
  $m2 = "no-cors"
   
  $a1 = "fetchWithTimeout"
  $a2 = "CONCURRENCY_LIMIT"
  $a3 = "flood"
  
 condition:
  (
   all of ($s*) and
   for all of ($f*): (# == 1) and
   all of ($m*)
  ) or
  (
   all of ($s*) and
   2 of ($a*)
  )
}

 

rule MAL_BrownFlood_2
{
 meta:
  description = "To detect BrownFlood JavaScript DDoS implant (base64 encoded)"
  author = "CERT-UA"
  created = "2022-04-27"
  version = 2

 strings:
  $s1 = "http://" base64
  $s2 = "https://" base64
   
  $i = " fetch(" base64

  $f1 = "AbortController()" base64
  $f2 = "Math.random()" base64
  $f3 = "await " base64
  $f4 = ".shift(" base64
  $f5 = ".push(" base64

  $m1 = "GET" base64
  $m2 = "no-cors" base64
   
  $a1 = "fetchWithTimeout" base64
  $a2 = "CONCURRENCY_LIMIT" base64
  $a3 = "flood" base64
  
 condition:
  (
   any of ($s*) and
   $i and
   for all of ($f*): (# < 6) and
   all of ($m*)
  )
  or
  (
   any of ($s*) and
   $i and
   2 of ($a*)
  )
}
