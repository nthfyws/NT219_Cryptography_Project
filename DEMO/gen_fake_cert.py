import subprocess

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True)
    if result.returncode != 0:
        print(result.stderr.decode())
        raise RuntimeError("Lệnh thất bại!")
    else:
        print(result.stdout.decode())

# 1. Sinh private key
run_cmd("openssl genpkey -provider oqsprovider -provider default -algorithm mldsa65 -out fake.key")

# 2. Sinh self-signed certificate
run_cmd('openssl req -new -x509 -provider oqsprovider -provider default -key fake.key -out fake.crt -subj "/CN=Fake User"')

# 3. Đóng gói thành file .pfx
run_cmd("openssl pkcs12 -export -provider oqsprovider -provider default -out fake.pfx -inkey fake.key -in fake.crt -passout pass:123456")

print("Đã tạo xong fake.key, fake.crt, fake.pfx!")