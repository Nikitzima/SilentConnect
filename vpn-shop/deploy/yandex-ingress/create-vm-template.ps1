# Template. Run after `yc init` has selected silentconnect-cloud.
# Fill $HOME_IP if you want SSH locked down at security group level.

$ErrorActionPreference = "Stop"

$YC = "$env:USERPROFILE\yandex-cloud\bin\yc.exe"
$ZONE = "ru-central1-b"
$NETWORK = "silentconnect-net"
$SUBNET = "silentconnect-ru-b"
$SG = "silentconnect-ingress-sg"
$ADDRESS = "silentconnect-ingress-ip"
$VM = "silentconnect-ingress-1"
$HOME_IP = "<YOUR_HOME_PUBLIC_IP>/32"
$SSH_KEY = "$env:USERPROFILE\.ssh\id_ed25519.pub"

& $YC vpc network create --name $NETWORK
& $YC vpc subnet create --name $SUBNET --zone $ZONE --network-name $NETWORK --range "10.20.0.0/24"

& $YC vpc security-group create --name $SG --network-name $NETWORK `
  --rule "direction=ingress,protocol=tcp,port=22,v4-cidrs=$HOME_IP" `
  --rule "direction=ingress,protocol=tcp,port=443,v4-cidrs=[0.0.0.0/0]" `
  --rule "direction=ingress,protocol=tcp,port=8443,v4-cidrs=[0.0.0.0/0]" `
  --rule "direction=egress,protocol=any,v4-cidrs=[0.0.0.0/0]" `
  --rule "direction=egress,protocol=any,v6-cidrs=[::/0]"

& $YC vpc address create --name $ADDRESS --external-ipv4 zone=$ZONE --deletion-protection
$YANDEX_IP = (& $YC vpc address get --name $ADDRESS --format json | ConvertFrom-Json).external_ipv4_address.address

& $YC compute instance create `
  --name $VM `
  --zone $ZONE `
  --cores 2 `
  --memory 2GB `
  --create-boot-disk image-family=ubuntu-2404-lts,size=20GB,type=network-ssd `
  --network-interface subnet-name=$SUBNET,nat-address=$YANDEX_IP,security-group-names=$SG `
  --ssh-key $SSH_KEY

Write-Host "Yandex ingress VM IP: $YANDEX_IP"
Write-Host "Next:"
Write-Host "scp vpn-shop/deploy/yandex-ingress/bootstrap-haproxy-relay.sh yc-user@${YANDEX_IP}:/tmp/"
Write-Host "ssh yc-user@${YANDEX_IP} 'sudo bash /tmp/bootstrap-haproxy-relay.sh'"
