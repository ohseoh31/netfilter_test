# netfilter_test


### 네트워크 필터를 통한 sex.com 차단코드 작성

1. 네트워크로 들어오는 패킷을 가상의 que에 넣어 중간에서 제어를 한다.

```
iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE 

```


2. ip 해더 tcp 해더를 확인한다

3. HTTP 프로토콜중 GET 으로 들어온 패킷을 확인한다.

4. 지정해놓은 URL을 요청하는 경우 차단한다.
