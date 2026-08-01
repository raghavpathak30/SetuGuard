import urllib.request, io, uuid

csv = 'account_id,label,feature1\n1,0,0.1\n2,1,0.9\n3,0,0.2\n4,1,0.8\n'
boundary = '----WebKitFormBoundary' + uuid.uuid4().hex
body = io.BytesIO()
body.write(f'--{boundary}\r\n'.encode())
body.write(b'Content-Disposition: form-data; name="dataset"; filename="test.csv"\r\n')
body.write(b'Content-Type: text/csv\r\n\r\n')
body.write(csv.encode())
body.write(f'\r\n--{boundary}--\r\n'.encode())
req = urllib.request.Request('http://127.0.0.1:5000/api/analyze_dataset', data=body.getvalue(), method='POST')
req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
try:
    with urllib.request.urlopen(req, timeout=20) as res:
        print('status', res.status)
        data = res.read().decode()
        print('response:', data[:2000])
except Exception as e:
    print('request failed:', type(e).__name__, e)
