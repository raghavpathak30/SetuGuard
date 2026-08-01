import sys
try:
    import requests
except Exception:
    print('requests not installed; try: pip install requests')
    sys.exit(1)

csv = 'account_id,label,feature1\n1,0,0.1\n2,1,0.9\n3,0,0.2\n4,1,0.8\n'
files = {'dataset': ('test.csv', csv, 'text/csv')}
try:
    r = requests.post('http://127.0.0.1:5000/api/analyze_dataset', files=files, timeout=10)
    print('status', r.status_code)
    try:
        print('json:', r.json())
    except Exception:
        print('text:', r.text[:1000])
except Exception as e:
    print('request failed:', e)
