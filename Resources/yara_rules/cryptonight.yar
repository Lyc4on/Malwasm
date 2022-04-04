rule cryptonight_signatures {
   meta:
      description = "cryptonight detection"
      author = "Lycaon"
      date = "2022-04-4"
   strings:
      $s1 = "cryptonight_hash"
      $s2 = "cryptonight_create"
      $s3 = "cryptonight_destroy"
   condition:
      any of them
}