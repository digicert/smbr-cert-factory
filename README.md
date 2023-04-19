# S/MIME Baseline Requirements Certificate Factory

## What is this project?

This project generates example S/MIME certificates that comply with version 1.0 of the CA/Browser Forum
[Baseline Requirements for the Issuance and Management of Publicly-Trusted S/MIME Certificates](https://cabforum.org/smime-br/).

## How do I run this on my local machine?

1. Install Python 3.
2. Clone this repository (`git clone https://github.com/digicert/smbr-cert-factory.git`).
3. `cd` to the root of the cloned repository (`cd smbr-cert-factory`).
4. Install required packages (`pip3 install -r requirements`).
5. Run `python3 main.py`. Example certificates, CRLs, and private keys will be output to the `artifacts` directory.

## The example S/MIME certificates

These example certificates were generated by running this project locally. Note that the key pairs used by this project are
sourced from [Standard PKC Test Keys](https://www.ietf.org/archive/id/draft-gutmann-testkeys-03.html). If you run a CA,
we highly recommend that you add these keys to your blocklist.

* [Root CA](https://understandingwebpki.com?cert=MIIB5TCCAYugAwIBAgIUZaqXQ%2B5MTw3Pf0ca02IAbY/BL3gwCgYIKoZIzj0EAwIwQDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0ZWQxEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMjMwNDE5MDAwMDAwWhcNMjQwNDEzMjM1OTU5WjBAMQswCQYDVQQGEwJVUzEfMB0GA1UECgwWRm9vIEluZHVzdHJpZXMgTGltaXRlZDEQMA4GA1UEAwwHUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEIlSPiPt4L/teyjdERSxyoeVY%2B9b3O%2BXkjpMjLMRcWxbEzRDEy41bihcTnpSILImSVymTQl9BQZq36QpCpJQnKjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB8GA1UdIwQYMBaAFFtwp5gX95/2N9L349xEbCEJ17vUMB0GA1UdDgQWBBRbcKeYF/ef9jfS9%2BPcRGwhCde71DAKBggqhkjOPQQDAgNIADBFAiEA3zlK5ulkcvDSLWOwvTqDQRUESBfiFbsRTnxc3alkAfcCIFk%2Bh0%2BQlSxYdz1Wn7mxHkMjmo/hfxhaFEaE8JI6AbxR)
* [Issuing CA](https://understandingwebpki.com?cert=MIIEdzCCBB2gAwIBAgIUOVIapcdUSrnN9mVhkYrkAfpWTiswCgYIKoZIzj0EAwIwQDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0ZWQxEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMjMwNDE5MDAwMDAwWhcNMjMxMDE2MjM1OTU5WjBIMQswCQYDVQQGEwJVUzEfMB0GA1UECgwWRm9vIEluZHVzdHJpZXMgTGltaXRlZDEYMBYGA1UEAwwPSW50ZXJtZWRpYXRlIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAs4tJYOY75qjbqJqCl47x9jJE5Vd9jPWGFtXKV1nUnMjZNsM4qjy5sRHBSX5bUa9pLyYR5on3Z1SAwLD0w2VPQ6%2BF/oyK1zTgQqitoF/XZQjgC6D3VsNEO76DPqfRANT7Nn7r1gvbZIZ3/H3rlCRNrRr47tHGWBLAPnxz9/NY6UG8ZkWP97uXpJqYoRgH4CwaO5rTOlc64YDh/0Mq5VgMycq/q2AvMlvNoJfoe8em1040qH1gikP%2BsuT/8fS452hqmEddtRpuvQgXKldBd0kkiyFVyLkG4NVA6Mso9MAK3J/kdYoaw2SrOeThVSiYVEQVP%2B7GrUxTSLLjj/VQ9fpYM5eTNzDICIG/Ee7o/jhtW1EoSamDmUOr89lyIHaXuOwkEaJhnVXKBCM8WiztxvKG2CnQ6Dcge3ZSmqJEhyEmjcAVC7ewfnMxOnE%2BWJW6rzrf%2BmA5WMVn%2BFzyWx2AondWow0aUKHkaY7amhIrsKp6YPfNImyxFlz8%2BcqDCmBswPsUh/JJ5eDHHIhibFcSgIHedsEjhLbUSLZ/DnEjru90qIWWA3R1VIPykKfeZkZeInsrFzGPikkFKwFF%2B6KDdyvCmltYEqzO46tigXAZ5UgH8oiXEre48wO6X%2BFH%2BcLzQ0q3A8HZRnNDgqCjU/Tgy76iaku/Ic6eteedR1fX3gJ/IOUCAwEAAaOCASAwggEcMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMB8GA1UdIwQYMBaAFFtwp5gX95/2N9L349xEbCEJ17vUMB0GA1UdDgQWBBTWRAAyfKgN/6xPa2buta6bLMU4VDARBgNVHSAECjAIMAYGBFUdIAAwOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybC5jYS5leGFtcGxlLmNvbS9yb290X2NhX2NybC5jcmwwSAYIKwYBBQUHAQEEPDA6MDgGCCsGAQUFBzAChixodHRwOi8vcmVwb3NpdG9yeS5jYS5leGFtcGxlLmNvbS9yb290X2NhLmRlcjAdBgNVHSUEFjAUBggrBgEFBQcDBAYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDSAAwRQIhANKIDSzhMyf8aY9p5N/jJ/csMsHVmtF0a4iAE8pmnHkdAiAUzKyUNYeglKf3rbkXwWlSZtvIVu8vXSFmgVnhcwrc9Q%3D%3D)
* [Mailbox-Validated Strict](https://understandingwebpki.com?cert=MIIFjTCCA3WgAwIBAgIUd6S3Xz8ATQGFzml1vs49vkKoG3owDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MTkwMDAwMDBaFw0yMzA3MTgyMzU5NTlaME4xIjAgBgNVBAMMGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb20xKDAmBgkqhkiG9w0BCQEWGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCw%2BegZQ6eumJKq3hfKfED4dE/tL4FI5sjqont9ABVI%2B1GSqyi1bFBgsRjM0THllIdMbKmJtWwnKW8J%2B5OgNN8y6Xxv8JmM/Y5vQt2lis0fqXmG8UTz0VTWdlAXXmhUs6lSADvAaIe4RVrCsZ97L3ZQTryY7JRVcbB4khUN3Gp0yg%2B801SXzoFTTa%2BUGIRLE66jH51aa5VXu99hnv1OiH8tQrjdi8mH6uG/icq4XuIeNWMF32wHqIOOPvQcWV3M5D2vxJEj702Ku6k9OQXkAo17qRSEonWW4HtLbtmS8He1JNPc/n3dVUm%2BfM6NoDXPoLP7j55G9zKyqGtGAWXAj1MTAgMBAAGjggFnMIIBYzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBTWRAAyfKgN/6xPa2buta6bLMU4VDAdBgNVHQ4EFgQUiRlZXg7xafXLvUfhNPzimMxpMJEwFAYDVR0gBA0wCzAJBgdngQwBBQEDMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYV9jcmwuY3JsMEsGCCsGAQUFBwEBBD8wPTA7BggrBgEFBQcwAoYvaHR0cDovL3JlcG9zaXRvcnkuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYS5kZXIwEwYDVR0lBAwwCgYIKwYBBQUHAwQwTAYDVR0RBEUwQ4EZaGFuYWtvLnlhbWFkYUBleGFtcGxlLmNvbaAmBggrBgEFBQcICaAaDBjlsbHnlLDoirHlrZBAZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggIBAGLGFYwy/Y2171NnkReQGX7DrgsoOpQAcl2g92D3SVBdrI2yr5hf2W8Dh7c/lDQ2nmSLEGuRdc2PqhQK4gDXCgzgQ5BJQsDDxNj7%2B5Kj6HOi8u1FdQRSNDD/odIjGp6j8B9dvU6%2Bj622Xx2MmIgX7fYzpd36P5MOWhFN9pWpXQ/eH/lgOAonzgVmnhr0rQ4E5u3zHzYxSInRrERvjG5LfStqckh04OZF8K9Px5vprfFkvNgIMqGu%2B3fwhcJQG40W9ibIDOfvMpHPNn6TyV0/6KPTPqTtR0mLNbyWNDG8NrElSD4ShpswsFuxRAQcMuHP0AXarijVphATvNlypZVb4ihoGKmX86FFRR0T7JjUGxOYoCCvyBO1ZzAfeKgNdFwbx8JKhRkSUwHiDvgwgUwKpwmzwNTu9uMlltHO/LMcw45kMFiQOWRJ9sv0SkQnKqkMaC6xo1NWC71JON4Y/3L9Av/Az3lZFxJWLB8V1H%2BFs/x/7o8J9Y44tclOUNeC8y50ymzJEAxidCk4vBgpDnlF3u2Rai9jZi0o2NxF2LhIuKyahnSi/1%2BV8jxZuWkEiuRJptBsXGFt2pgFvQC9%2B87LV/J5R%2BH81/wNVnHlb0S%2B3HNgSJrU17MFnjUSy3%2BOvHmLoWizcbrR/04H1p8d9PYC4Qdtu3htzrgJImFgWZZtBYPb)
* [Mailbox-Validated Multipurpose](https://understandingwebpki.com?cert=MIIFwjCCA6qgAwIBAgIUH/nOhctN2lspZ2LasyeIMEixJzEwDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MTkwMDAwMDBaFw0yMzA3MTgyMzU5NTlaME4xIjAgBgNVBAMMGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb20xKDAmBgkqhkiG9w0BCQEWGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCw%2BegZQ6eumJKq3hfKfED4dE/tL4FI5sjqont9ABVI%2B1GSqyi1bFBgsRjM0THllIdMbKmJtWwnKW8J%2B5OgNN8y6Xxv8JmM/Y5vQt2lis0fqXmG8UTz0VTWdlAXXmhUs6lSADvAaIe4RVrCsZ97L3ZQTryY7JRVcbB4khUN3Gp0yg%2B801SXzoFTTa%2BUGIRLE66jH51aa5VXu99hnv1OiH8tQrjdi8mH6uG/icq4XuIeNWMF32wHqIOOPvQcWV3M5D2vxJEj702Ku6k9OQXkAo17qRSEonWW4HtLbtmS8He1JNPc/n3dVUm%2BfM6NoDXPoLP7j55G9zKyqGtGAWXAj1MTAgMBAAGjggGcMIIBmDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBTWRAAyfKgN/6xPa2buta6bLMU4VDAdBgNVHQ4EFgQUiRlZXg7xafXLvUfhNPzimMxpMJEwFAYDVR0gBA0wCzAJBgdngQwBBQECMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYV9jcmwuY3JsMEsGCCsGAQUFBwEBBD8wPTA7BggrBgEFBQcwAoYvaHR0cDovL3JlcG9zaXRvcnkuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYS5kZXIwHQYDVR0lBBYwFAYIKwYBBQUHAwQGCCsGAQUFBwMCMHcGA1UdEQRwMG6BGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb22gKQYKKwYBBAGCNxQCA6AbDBloYW5ha28ueWFtYWRhQGV4YW1wbGUuY29toCYGCCsGAQUFBwgJoBoMGOWxseeUsOiKseWtkEBleGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAgEAg4rIcKGMfLh347FX/Y12lx7b9/iVrjsX7lsliirpITuPmfCli76JVrO0Fqypfdd2P4ZVvH9WTpQUhRBv06kwHkJRkgpqNPO0WOpNVnsK8vcP1/RylDiJGryzu6AzOSDqsxomFD6hm71XRYcsgBXXNPUzSGhbqUeuBuZwZe1WmP/yuvNpghMvlWFcjAHktC9FuNpHhQ/3zZ20GUc6AQwwtn8rviFSwQihVJDJkGiGaJUc7lVVoswx87bSoGpVluEIY/RK2HsXU0kmek4qq2t9v1OgRL98ZqUgOS26ooOXxqnR3QMx1S5KSLy9%2BhK6y2gPhyiHoaPVTk4s54Es/YDtbCz7piyyyp3DEIzmgrwB/mG2IbOv6dT8Za5BR7A%2BggB7uwo3zYxKd2SFIDmXb%2Bn9ML/s6/3aeyKJms4FmRq%2BfX8icb%2BlvVeLMhlCRe5MFL2tkb72BFku0eeUde4iUnw93fzG6%2BWl8VPCzYOwV0j%2BUTiyygcXaEZW%2BTpTEmyY/fQ/7TCbGp%2B8Ur3rLlY5Okt5T83MmZdMFIHLQxaZUXkT2dBaSnh3VfNKFi0are9xdiBQZGkMkvWiKTjrUOwLXSNBnP6TXO9zn51tTK4KPZnQvNvULtn4H7z3FhfWkie/jPNYkFvMzOaawwPAhG9R6G2ZB7cTOuG0Uu863Hkh5XX2oAo%3D)
* [Organization-Validated Strict](https://understandingwebpki.com?cert=MIIGJTCCBA2gAwIBAgIUVVqfvGiErUkRzwZ09xzjZpwLC0QwDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MTkwMDAwMDBaFw0yMzA3MTgyMzU5NTlaMG8xIzAhBgNVBGETGkxFSVhHLUFFWUUwMEVLWEVTVlpVVUVCUDY3MR4wHAYDVQQKExVBY21lIEluZHVzdHJpZXMsIEx0ZC4xKDAmBgkqhkiG9w0BCQEWGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCw%2BegZQ6eumJKq3hfKfED4dE/tL4FI5sjqont9ABVI%2B1GSqyi1bFBgsRjM0THllIdMbKmJtWwnKW8J%2B5OgNN8y6Xxv8JmM/Y5vQt2lis0fqXmG8UTz0VTWdlAXXmhUs6lSADvAaIe4RVrCsZ97L3ZQTryY7JRVcbB4khUN3Gp0yg%2B801SXzoFTTa%2BUGIRLE66jH51aa5VXu99hnv1OiH8tQrjdi8mH6uG/icq4XuIeNWMF32wHqIOOPvQcWV3M5D2vxJEj702Ku6k9OQXkAo17qRSEonWW4HtLbtmS8He1JNPc/n3dVUm%2BfM6NoDXPoLP7j55G9zKyqGtGAWXAj1MTAgMBAAGjggHeMIIB2jAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBTWRAAyfKgN/6xPa2buta6bLMU4VDAdBgNVHQ4EFgQUiRlZXg7xafXLvUfhNPzimMxpMJEwFAYDVR0gBA0wCzAJBgdngQwBBQIDMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYV9jcmwuY3JsMEsGCCsGAQUFBwEBBD8wPTA7BggrBgEFBQcwAoYvaHR0cDovL3JlcG9zaXRvcnkuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYS5kZXIwEwYDVR0lBAwwCgYIKwYBBQUHAwQwgZ0GA1UdEQSBlTCBkoEZaGFuYWtvLnlhbWFkYUBleGFtcGxlLmNvbaAmBggrBgEFBQcICaAaDBjlsbHnlLDoirHlrZBAZXhhbXBsZS5jb22kTTBLMSMwIQYDVQRhExpMRUlYRy1BRVlFMDBFS1hFU1ZaVVVFQlA2NzEkMCIGA1UECgwb44Ki44Kv44Of5bel5qWt5qCq5byP5Lya56S%2BMCMGCSsGAQQBg5gqAQQWExRBRVlFMDBFS1hFU1ZaVVVFQlA2NzANBgkqhkiG9w0BAQsFAAOCAgEAVUXkfu8EGZEmUAh1INwCCFMN898yDR/kP5wWzhJBQnFxL5h48lr7F3f2%2BlJCS0etGxSOpTSOvniIVT8CYwzZ35AVS/7V0vlsJNk/ahurYD3ku0IEo9mU0Z/7Bv8PMolKs1rNNbZ0vUXHoZlfmLF927IjooCEHAYwRmeWtcmWxlqHgGXVFHwriBpsZCFpkGyfD4uvpuWn/qBOv7b5zdJU7/uP9KHrhALDLmpPoUudgGKIStj8klUnf0RhiVjrQsNDHblRWwZ5fDpj3pUlLPiBtCpKczg1sX7Tb4rhdPaXar23H1j6WbZTap5bZSAuhOqcNPN5jA7v0C%2BccQbaoOu%2BFwHn2bIltewBRuXJMJWBrKAnlVLarrc%2BkE7dheWUFiPAxbIPlH1Oaar0i8NY1BAGjX3AQgoieyaX8rlMqmfQSyV2wzPL3B25sudoiSo%2Bbjv5k4IaWlp0W2c/Nc5iefZhLhRulwmVaFVzlarZL6iThrKp%2BPLeBwPeVdiwZdbMk0N6Dlt7j3DWSoLq9aXVaPhqaAGrRUcD3sHnlbbbFzAOpncVZGqLrT159vKnLwdVmoNfvMJEOs8By/qqeLiMxlfbmTjrYqX5LE2fVzWNyirU/PxAezXTvxiZ0RGxpExSWraKQTu05AsvsAnQYxYalCd3v3uwx02sYnbhJdckhTEJdEE%3D)
* [Organization-Validated Multipurpose](https://understandingwebpki.com?cert=MIIGWjCCBEKgAwIBAgIUEt8E6/C2aDHaKEEUTNRH3EtHq6swDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MTkwMDAwMDBaFw0yMzA3MTgyMzU5NTlaMG8xIzAhBgNVBGETGkxFSVhHLUFFWUUwMEVLWEVTVlpVVUVCUDY3MR4wHAYDVQQKExVBY21lIEluZHVzdHJpZXMsIEx0ZC4xKDAmBgkqhkiG9w0BCQEWGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCw%2BegZQ6eumJKq3hfKfED4dE/tL4FI5sjqont9ABVI%2B1GSqyi1bFBgsRjM0THllIdMbKmJtWwnKW8J%2B5OgNN8y6Xxv8JmM/Y5vQt2lis0fqXmG8UTz0VTWdlAXXmhUs6lSADvAaIe4RVrCsZ97L3ZQTryY7JRVcbB4khUN3Gp0yg%2B801SXzoFTTa%2BUGIRLE66jH51aa5VXu99hnv1OiH8tQrjdi8mH6uG/icq4XuIeNWMF32wHqIOOPvQcWV3M5D2vxJEj702Ku6k9OQXkAo17qRSEonWW4HtLbtmS8He1JNPc/n3dVUm%2BfM6NoDXPoLP7j55G9zKyqGtGAWXAj1MTAgMBAAGjggITMIICDzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBTWRAAyfKgN/6xPa2buta6bLMU4VDAdBgNVHQ4EFgQUiRlZXg7xafXLvUfhNPzimMxpMJEwFAYDVR0gBA0wCzAJBgdngQwBBQICMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYV9jcmwuY3JsMEsGCCsGAQUFBwEBBD8wPTA7BggrBgEFBQcwAoYvaHR0cDovL3JlcG9zaXRvcnkuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYS5kZXIwHQYDVR0lBBYwFAYIKwYBBQUHAwQGCCsGAQUFBwMCMIHIBgNVHREEgcAwgb2BGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb22gKQYKKwYBBAGCNxQCA6AbDBloYW5ha28ueWFtYWRhQGV4YW1wbGUuY29toCYGCCsGAQUFBwgJoBoMGOWxseeUsOiKseWtkEBleGFtcGxlLmNvbaRNMEsxIzAhBgNVBGETGkxFSVhHLUFFWUUwMEVLWEVTVlpVVUVCUDY3MSQwIgYDVQQKDBvjgqLjgq/jg5/lt6Xmpa3moKrlvI/kvJrnpL4wIwYJKwYBBAGDmCoBBBYTFEFFWUUwMEVLWEVTVlpVVUVCUDY3MA0GCSqGSIb3DQEBCwUAA4ICAQCUTWvDqSw63QWmuv7nd4JrAL3gEkgmlcH0K%2Bs61dS84xMOqiNVtrnqnig1Saw8gI6zCGx0YiM6oqXuBFYoX%2BcbkjtY6l61bKgSrZNBp9TmK/TtgF5CHFX1TpJctiBiyqkrqcBhJ5X6NhW3aS2pTt/spA27QKhi9tddwoFKGQvlFV5Q3e4KsW%2B3PSCfI9KbwrpYyFcqBvgXGr%2BRqYAIdUbPiWH8Xc%2BAVbCkT678o17JRimJLGLIuOGab7Ld56So2R7lV3cQXU%2B4b4hpBr7EYTasKUWt7t6dyN6QTgqkykWb/V7YkEcpBMzZT9G6PHGjv1APupPQCXd2xPSkBRW77/F4AkmNp9Dt1VERBXzG09pzvLVkBNutICAvHVEZzivPd3pl80A7oHezMemNpyx0C4OxwVT5OT5gCb5XD45u2%2BqJmK6ws1gbu8HlmFKFvLdg8Vokr6EieyvFcq2wYWX0TnY1K5KDi2CHMt6xdmvNLh2tVLuwFH6edbFxQXrrFcplr%2B0DB7ljUYNZe69XEkbrv7AOMumE%2B3WD6QP8cQDnn9LmNJrJu0LynzC9ij7X/wrl5%2BJH16fmgQ44TeUI1CmTvQrUXCSQGHIoTC8gGTD6n4ukzkYWatB/Jz%2BAqwstGDsqBcu4Rnxdtj8QVKoEbjv9qkSR2F7olSOoK2nOG%2BIhxk04Kw%3D%3D)
* [Sponsored-Validated Strict](https://understandingwebpki.com?cert=MIIGrzCCBJegAwIBAgIUYsQ%2BFan%2BRfQ1ToEaA%2BPeZh43OTEwDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MTkwMDAwMDBaFw0yMzA3MTgyMzU5NTlaMIGpMSMwIQYDVQRhExpMRUlYRy1BRVlFMDBFS1hFU1ZaVVVFQlA2NzEeMBwGA1UEChMVQWNtZSBJbmR1c3RyaWVzLCBMdGQuMQ8wDQYDVQQEDAZZYW1hZGExDzANBgNVBCoMBkhhbmFrbzEWMBQGA1UEAwwNWUFNQURBIEhhbmFrbzEoMCYGCSqGSIb3DQEJARYZaGFuYWtvLnlhbWFkYUBleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALD56BlDp66YkqreF8p8QPh0T%2B0vgUjmyOqie30AFUj7UZKrKLVsUGCxGMzRMeWUh0xsqYm1bCcpbwn7k6A03zLpfG/wmYz9jm9C3aWKzR%2BpeYbxRPPRVNZ2UBdeaFSzqVIAO8Boh7hFWsKxn3svdlBOvJjslFVxsHiSFQ3canTKD7zTVJfOgVNNr5QYhEsTrqMfnVprlVe732Ge/U6Ify1CuN2LyYfq4b%2BJyrhe4h41YwXfbAeog44%2B9BxZXczkPa/EkSPvTYq7qT05BeQCjXupFISidZbge0tu2ZLwd7Uk09z%2Bfd1VSb58zo2gNc%2Bgs/uPnkb3MrKoa0YBZcCPUxMCAwEAAaOCAi0wggIpMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB8GA1UdIwQYMBaAFNZEADJ8qA3/rE9rZu61rpssxThUMB0GA1UdDgQWBBSJGVleDvFp9cu9R%2BE0/OKYzGkwkTAUBgNVHSAEDTALMAkGB2eBDAEFAwMwPQYDVR0fBDYwNDAyoDCgLoYsaHR0cDovL2NybC5jYS5leGFtcGxlLmNvbS9pc3N1aW5nX2NhX2NybC5jcmwwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vcmVwb3NpdG9yeS5jYS5leGFtcGxlLmNvbS9pc3N1aW5nX2NhLmRlcjATBgNVHSUEDDAKBggrBgEFBQcDBDCB2AYDVR0RBIHQMIHNgRloYW5ha28ueWFtYWRhQGV4YW1wbGUuY29toCYGCCsGAQUFBwgJoBoMGOWxseeUsOiKseWtkEBleGFtcGxlLmNvbaSBhzCBhDEjMCEGA1UEYRMaTEVJWEctQUVZRTAwRUtYRVNWWlVVRUJQNjcxJDAiBgNVBAoMG%2BOCouOCr%2BODn%2BW3pealreagquW8j%2BS8muekvjEPMA0GA1UEBAwG5bGx55SwMQ8wDQYDVQQqDAboirHlrZAxFTATBgNVBAMMDOWxseeUsOiKseWtkDAjBgkrBgEEAYOYKgEEFhMUQUVZRTAwRUtYRVNWWlVVRUJQNjcwEgYJKwYBBAGDmCoCBAUTA0NFTzANBgkqhkiG9w0BAQsFAAOCAgEAE/8rQdESC9lQcnw5TnIj/DhzWqrE6S4I1F7LFgUNQB5GJUSUbnFdeExwfV%2Btbjloht4frY7oJvvYyjT2t5/nv2Hrfpe95KmRhliEkEfs3ri5J/pMHa5ju1Kox49nm8OjKkon9HMK6c7IJy2Ow1yrwDYDflVeMmZUvMr%2BEmUk6BdRtF40ljNwLw8xJZfhxUzo1OjaTKu7gtYqzrFhEqijpVoxtWIBLgL7IAujPYONrxeffJ7DY6vWzBVG4C%2B7iuqlrf6Y2f25yfEp0Hs9kBD26xEZUg43Zl7BxaBbJLesUk2FRD1B/N5DYZecTc7WF1a1YUW5N15wskn8SZAXIz9xx8OThu9v7eP3qpUNaU%2BiaTqbjxTPGiSUYa3Jrm1yAbh4XCOUfb4UJo23uHsNZyoLOX8lVOsesLOE/BGvlKHzT0x49uNKZq0O6lU9fxFtiM4MRNqmNZTN9jZ1yu06cuI8nr8AEWt7Hp5OTldj5KXZFd945DqWyZHx01Uv/w5ZU8/E3Jf1bDTbf5OLWqombrgLIWL%2BA/SrRvnqyLpyDv2PHJ0IgbsylDRalxeGHa1Q3egwHqkYRzYOy3LYRphJITSGCnqRGshySonks4osE7KbXFwMEEmEWlF1S7S%2BVDkqEqpda1II90v7ae6kNwIPK%2B140WOhkKilZ526OHvetaZ9XUc%3D)
* [Sponsored-Validated Multipurpose](https://understandingwebpki.com?cert=MIIG5TCCBM2gAwIBAgIUbexY9Yq/5FVD85QkX3v/pCezY6IwDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MTkwMDAwMDBaFw0yMzA3MTgyMzU5NTlaMIGpMSMwIQYDVQRhExpMRUlYRy1BRVlFMDBFS1hFU1ZaVVVFQlA2NzEeMBwGA1UEChMVQWNtZSBJbmR1c3RyaWVzLCBMdGQuMQ8wDQYDVQQEDAZZYW1hZGExDzANBgNVBCoMBkhhbmFrbzEWMBQGA1UEAwwNWUFNQURBIEhhbmFrbzEoMCYGCSqGSIb3DQEJARYZaGFuYWtvLnlhbWFkYUBleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALD56BlDp66YkqreF8p8QPh0T%2B0vgUjmyOqie30AFUj7UZKrKLVsUGCxGMzRMeWUh0xsqYm1bCcpbwn7k6A03zLpfG/wmYz9jm9C3aWKzR%2BpeYbxRPPRVNZ2UBdeaFSzqVIAO8Boh7hFWsKxn3svdlBOvJjslFVxsHiSFQ3canTKD7zTVJfOgVNNr5QYhEsTrqMfnVprlVe732Ge/U6Ify1CuN2LyYfq4b%2BJyrhe4h41YwXfbAeog44%2B9BxZXczkPa/EkSPvTYq7qT05BeQCjXupFISidZbge0tu2ZLwd7Uk09z%2Bfd1VSb58zo2gNc%2Bgs/uPnkb3MrKoa0YBZcCPUxMCAwEAAaOCAmMwggJfMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB8GA1UdIwQYMBaAFNZEADJ8qA3/rE9rZu61rpssxThUMB0GA1UdDgQWBBSJGVleDvFp9cu9R%2BE0/OKYzGkwkTAUBgNVHSAEDTALMAkGB2eBDAEFAwIwPQYDVR0fBDYwNDAyoDCgLoYsaHR0cDovL2NybC5jYS5leGFtcGxlLmNvbS9pc3N1aW5nX2NhX2NybC5jcmwwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vcmVwb3NpdG9yeS5jYS5leGFtcGxlLmNvbS9pc3N1aW5nX2NhLmRlcjAdBgNVHSUEFjAUBggrBgEFBQcDBAYIKwYBBQUHAwIwggEDBgNVHREEgfswgfiBGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb22gKQYKKwYBBAGCNxQCA6AbDBloYW5ha28ueWFtYWRhQGV4YW1wbGUuY29toCYGCCsGAQUFBwgJoBoMGOWxseeUsOiKseWtkEBleGFtcGxlLmNvbaSBhzCBhDEjMCEGA1UEYRMaTEVJWEctQUVZRTAwRUtYRVNWWlVVRUJQNjcxJDAiBgNVBAoMG%2BOCouOCr%2BODn%2BW3pealreagquW8j%2BS8muekvjEPMA0GA1UEBAwG5bGx55SwMQ8wDQYDVQQqDAboirHlrZAxFTATBgNVBAMMDOWxseeUsOiKseWtkDAjBgkrBgEEAYOYKgEEFhMUQUVZRTAwRUtYRVNWWlVVRUJQNjcwEgYJKwYBBAGDmCoCBAUTA0NFTzANBgkqhkiG9w0BAQsFAAOCAgEAp3tXel6XoR3ZGpmKzSb/BKYBusHmXUdAcUlHqkUQBe5NUDJOjemWUZMonotbbJuee62dGpOE8XyIEzgZeBiFduIbsXCTgIzzzxn01HxISILHcfq20SrvYJ6JH%2BQ%2Bfznh7leFEXnVinr25TFJ/XmZsMNC51Z6dWKkrQRjOxFH690/F8LWwy%2B8s5JgIQHJIxbo70YQ8Uu5hu56DoiI1itEm9vyxnR%2B%2BKEZb5ELDLhawgxFnZXFeHdaJzJtihpiGj8sYgR4MaQAyuNsDDhgKjoKUs6wfkbzoUtXAmmLFWLTt4FeJqk6jyRxurt3whRNGOWNSEmv3jZAqCsRz%2BPHosUE4WcARtUDPT4ioPxdpSraDa9VktMRPeEx4TUXwu/AE79NzNsZKhlDMp0WyEwvz0RNNMi7DK4mE/3eDK%2B2OP7y2Qyocu8DSu8BgzwUx1GdSHVI6/1RorV5aG37DqCpmBR1tHdj9QpjMbAZANtrtCyPWX/Larau9b%2BqTFKfhPslzUHq4xzuDPAhcksfSIk6pWigBuAc0nn1I4f3%2BfIMA/4b6R%2BIz3qlMg6/if8k7bQ5lT8JxeVl58Nij%2B4QvZAK6M9kJhrnpd7PqrAGKbQ6vc/Fcf6U6mV2tgBPW3I7IbCAMOK2Kk8DSNq20a1iOC/0wg5wYKFNBLoFizSvyci5JKTN3g0%3D)
* [Individual-Validated Strict](https://understandingwebpki.com?cert=MIIF4zCCA8ugAwIBAgIUOTexnaThhALqNKiaXDhQLJ/ZBXcwDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MTkwMDAwMDBaFw0yMzA3MTgyMzU5NTlaMGQxDzANBgNVBAQMBllhbWFkYTEPMA0GA1UEKgwGSGFuYWtvMRYwFAYDVQQDDA1ZQU1BREEgSGFuYWtvMSgwJgYJKoZIhvcNAQkBFhloYW5ha28ueWFtYWRhQGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsPnoGUOnrpiSqt4XynxA%2BHRP7S%2BBSObI6qJ7fQAVSPtRkqsotWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvNNUl86BU02vlBiESxOuox%2BdWmuVV7vfYZ79Toh/LUK43YvJh%2Brhv4nKuF7iHjVjBd9sB6iDjj70HFldzOQ9r8SRI%2B9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tSTT3P593VVJvnzOjaA1z6Cz%2B4%2BeRvcysqhrRgFlwI9TEwIDAQABo4IBpzCCAaMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHwYDVR0jBBgwFoAU1kQAMnyoDf%2BsT2tm7rWumyzFOFQwHQYDVR0OBBYEFIkZWV4O8Wn1y71H4TT84pjMaTCRMBQGA1UdIAQNMAswCQYHZ4EMAQUEAzA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY3JsLmNhLmV4YW1wbGUuY29tL2lzc3VpbmdfY2FfY3JsLmNybDBLBggrBgEFBQcBAQQ/MD0wOwYIKwYBBQUHMAKGL2h0dHA6Ly9yZXBvc2l0b3J5LmNhLmV4YW1wbGUuY29tL2lzc3VpbmdfY2EuZGVyMBMGA1UdJQQMMAoGCCsGAQUFBwMEMIGLBgNVHREEgYMwgYCBGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb22gJgYIKwYBBQUHCAmgGgwY5bGx55Sw6Iqx5a2QQGV4YW1wbGUuY29tpDswOTEPMA0GA1UEBAwG5bGx55SwMQ8wDQYDVQQqDAboirHlrZAxFTATBgNVBAMMDOWxseeUsOiKseWtkDANBgkqhkiG9w0BAQsFAAOCAgEAbPrqwt8aRFluaF5JUceC8%2BLS5rDr644ITGfJ%2B5KHJNo/O5HRjOj%2BndAsGyDgL0YuK2vQcP/r4IZ5kGeXFrc1a%2Bsrwo7ucnqX9RzJ4IQZ/q05W75sDtLd9uZeX734tlHkTlnCl%2BrBrF0g2Qjwe7/rI353OeXbKtG94aMVr4D70zdJq4w1fyms7do/GFv9JwI7%2BuuIpqjTf0lYvoWqnNwa1BozUaXz7WvvSKhE8Q6lQwXLQWRdTt5FAii0Rv8bfW7dKSmNJxrbRDfsF2aX568EaQODnJMxx4R%2BdWZaubT7R5ifJNgQb6wKhu%2B8Eeir2z%2BY2YFDSs%2B%2BDU/m3kFSD1aTOulLmgx5a2YyDLpdLMU45EaK9KuYK0mkUT4IvjJJ8wEfnjMB8A9pon3zDe6Pzfp1KVv2jTXnUCcyf47sPGuVR21ahGJWR1TElhyWTxAPpgRyeWjH%2BYR/brCxTcamT6W4l7Ltiy070K0MshytXojU3OuCFJcAnamYZ3RRQKLDyPZFKGGJ/Q1Rls/j9Oc62K5j5vJP5LZDnROZ1xUqXK42ntZQcQnw1HWEDIASkb/v7enAY/UjDKY9AcAvswvehzTA8szeGWgj5IwNCdtl7vQRGLM29OjYRf1SNm0Ds1IT2KtlyHT9GnaST7Jx7Gch2F2P04nkYmgCHvi6SnsfcUgkdTU%3D)
* [Individual-Validated Multipurpose](https://understandingwebpki.com?cert=MIIGGDCCBACgAwIBAgIUSQDmcRlGl6fjul/gHkKTHkLQl2QwDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MTkwMDAwMDBaFw0yMzA3MTgyMzU5NTlaMGQxDzANBgNVBAQMBllhbWFkYTEPMA0GA1UEKgwGSGFuYWtvMRYwFAYDVQQDDA1ZQU1BREEgSGFuYWtvMSgwJgYJKoZIhvcNAQkBFhloYW5ha28ueWFtYWRhQGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsPnoGUOnrpiSqt4XynxA%2BHRP7S%2BBSObI6qJ7fQAVSPtRkqsotWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvNNUl86BU02vlBiESxOuox%2BdWmuVV7vfYZ79Toh/LUK43YvJh%2Brhv4nKuF7iHjVjBd9sB6iDjj70HFldzOQ9r8SRI%2B9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tSTT3P593VVJvnzOjaA1z6Cz%2B4%2BeRvcysqhrRgFlwI9TEwIDAQABo4IB3DCCAdgwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHwYDVR0jBBgwFoAU1kQAMnyoDf%2BsT2tm7rWumyzFOFQwHQYDVR0OBBYEFIkZWV4O8Wn1y71H4TT84pjMaTCRMBQGA1UdIAQNMAswCQYHZ4EMAQUEAjA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY3JsLmNhLmV4YW1wbGUuY29tL2lzc3VpbmdfY2FfY3JsLmNybDBLBggrBgEFBQcBAQQ/MD0wOwYIKwYBBQUHMAKGL2h0dHA6Ly9yZXBvc2l0b3J5LmNhLmV4YW1wbGUuY29tL2lzc3VpbmdfY2EuZGVyMB0GA1UdJQQWMBQGCCsGAQUFBwMEBggrBgEFBQcDAjCBtgYDVR0RBIGuMIGrgRloYW5ha28ueWFtYWRhQGV4YW1wbGUuY29toCkGCisGAQQBgjcUAgOgGwwZaGFuYWtvLnlhbWFkYUBleGFtcGxlLmNvbaAmBggrBgEFBQcICaAaDBjlsbHnlLDoirHlrZBAZXhhbXBsZS5jb22kOzA5MQ8wDQYDVQQEDAblsbHnlLAxDzANBgNVBCoMBuiKseWtkDEVMBMGA1UEAwwM5bGx55Sw6Iqx5a2QMA0GCSqGSIb3DQEBCwUAA4ICAQBXAbbbyGLIBboQmz1d8XuWp37mMZtdSE%2BigZdsFmLu5mYrEflMQNw7S7m2sfuxt9Wrn/DCYpZGscGaZ56oe8DNnv55fR1zOSFmk1YTeeTjnRbVnL8tQqv%2BPE55EDKbSTNTbUNXKebH1%2BUs2nOjlVcN7z5jxPUKLDQ7bm2DFwMhxxV/WGiJQVbiLR8NucLHmk6s4m%2Br4y9CUAm/ViGftgglox%2BYYY1xirSswYP9Ufvda1FwSX0/RnJAXo23yvWmRRpgu3ot7BBC0iD43rpEKbXoCmLn/Zw8feefeD%2BMxyqRGfXC34JDrGzLcK9GNI1Dv9vCTQAVH2hL8bsyCGl6dkS6Ipda0cSG6%2BpVzHKQWYeVYHV39/FZ6Z/E9t/zeIPnSjZecJUjGMT5Pt1z38gFwkVsdL5y9I0uIMhMoUJ6Tx0ls%2B2CJ3s6Gt4CxljjDLK59gkjDmFdcCfdVHxd3oequzWpB8k1k7%2ByYefQHElXibexphce9Sbmo2h5J24dVTznq9WlTzGPJTF1eG9eyVyUsBe7CsrtmnY3/sWJOC1TviAO2bn7tcwrODzavxPHOHLeLwfbvSaGVAaQVM2BQN5hokqKj0Vb6OFH3xIBUvKBCvzT5ct%2BNObTRfHjnTRtMtJyXbVKRvc4VN7NZNIA6yv9HCYKwQDYzJLeSI1R7Hn0cw8S8Q%3D%3D)
* [Individual-Validated Legacy](https://understandingwebpki.com?cert=MIIF1DCCA7ygAwIBAgIUI%2Bv/jTtadau/a5lLVGP50z0FoW8wDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MTkwMDAwMDBaFw0yMzA3MTgyMzU5NTlaMEIxFjAUBgNVBAMMDVlBTUFEQSBIYW5ha28xKDAmBgkqhkiG9w0BCQEWGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCw%2BegZQ6eumJKq3hfKfED4dE/tL4FI5sjqont9ABVI%2B1GSqyi1bFBgsRjM0THllIdMbKmJtWwnKW8J%2B5OgNN8y6Xxv8JmM/Y5vQt2lis0fqXmG8UTz0VTWdlAXXmhUs6lSADvAaIe4RVrCsZ97L3ZQTryY7JRVcbB4khUN3Gp0yg%2B801SXzoFTTa%2BUGIRLE66jH51aa5VXu99hnv1OiH8tQrjdi8mH6uG/icq4XuIeNWMF32wHqIOOPvQcWV3M5D2vxJEj702Ku6k9OQXkAo17qRSEonWW4HtLbtmS8He1JNPc/n3dVUm%2BfM6NoDXPoLP7j55G9zKyqGtGAWXAj1MTAgMBAAGjggG6MIIBtjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBTWRAAyfKgN/6xPa2buta6bLMU4VDAdBgNVHQ4EFgQUiRlZXg7xafXLvUfhNPzimMxpMJEwFAYDVR0gBA0wCzAJBgdngQwBBQQBMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYV9jcmwuY3JsMEsGCCsGAQUFBwEBBD8wPTA7BggrBgEFBQcwAoYvaHR0cDovL3JlcG9zaXRvcnkuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYS5kZXIwHQYDVR0lBBYwFAYIKwYBBQUHAwQGCCsGAQUFBwMCMIGUBgNVHREEgYwwgYmBGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb22gKQYKKwYBBAGCNxQCA6AbDBloYW5ha28ueWFtYWRhQGV4YW1wbGUuY29toCYGCCsGAQUFBwgJoBoMGOWxseeUsOiKseWtkEBleGFtcGxlLmNvbaQZMBcxFTATBgNVBAMMDOWxseeUsOiKseWtkDANBgkqhkiG9w0BAQsFAAOCAgEAB3UHyqEUNiG3h2cDl9O0jfsIUwOSxSOoTI9X81QsoCb1JZpcDNJWyvBDalUSChHLAxBxImGa%2BWZw7dCFxhKLds8NKGtScefk7FNVxHT7iR77DcaqqyCz3UGYT5nwoPFMJ1Iu3Vb7h1zn9zHn9BlVCFEHr19ORXHpvjyi4cEU5/1zhfbm09tJE%2B2F4mrDK10AGG6BD6QTw0vV%2BvA%2BpSfxzcEmmfH0lcPLORgN4/A/bP4c57A7ZXG1YAbmEDJK07b6wF53EoUumalV7WvynrD9Jx1QrUera3yQLhOqfyWz7Ib2%2BdQnLlaLPw7n7gnSlo8EqfiyuY2XmOlr6i/KBGdWLnxE%2Bt1yC/YCFKVVykJEItSqyngEKAHZyu6Qh%2Bv68uorMO7nMhWQ/toLEeYxjig38qMi%2BoJ5oMeySlNKUQpLRTr7IRdvQ9gM2hHKTv/KrbmCa8vJv%2BpH0jbvE2WuHRkIQxmK/qYqkXKHcCHQU8NkafPEeQaE2hidSZV7AUzD4t2VoySASeh5qRC3QhNTIueFEjgBkJVGbynRnYIS9bOMsNASk8p5PYFcmDhHxOBHInjT5k%2Bai82xWruI5FV8ITf%2BqOiVgavPssSaYFtmhJZx0eimy04HG4O2CobSjQrt7Ue%2BYzzi/DWxhPfKPHOKTSqcxvS4ym37F2lybO2MTo%2BBW7w%3D)
 