echo "[ELIMINAZIONE CLASSI COMPILATE]"
rm -rf ./server/class/*
rm -rf ./client/class/*

printf "[ELIMINAZIONE UTENTI]\n"
rm -rf ./server/home/users/*

printf "[ELIMINAZIONE PROGETTI]\n"
rm -rf ./server/home/projects/*

printf "[RIPRISTINO IP MULTICAST INIZIALE]\n"
echo "239.0.0.0" > ./server/home/_ip/next_ip

printf "[RIPRISTINO LISTA IP RECUPERATI]\n"
echo "" > ./server/home/_ip/free_ip
