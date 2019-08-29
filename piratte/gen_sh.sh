# may need to 
 # comment out some portions
 # delete some files 
# before running this

# generate the sh files to test staffs
for i in 1 5 10 15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90 95 100
do
	for j in 1 2 3 4 5 6 7 8 9 10
	do
		echo "for i in 1 2 3 4 5" >> test_enc.sh
		echo "do" >> test_enc.sh
		echo "  cpabe-enc -k -o $i.$j.a.txt.cpabe pub_key a.txt '$policy'" >> test_enc.sh
		echo "done" >> test_enc.sh 
		
		echo "for i in 1 2 3 4 5" >> test_conv.sh
		echo "do" >> test_conv.sh
		echo "  cpabe-convert pub_key $i.$j.a.txt.cpabe revoked_list $1" >> test_conv.sh
		echo "done" >> test_conv.sh 
		
		echo "for i in 1 2 3 4 5" >> test_dec.sh
		echo "do" >> test_dec.sh
		echo "  cpabe-dec -k pub_key priv_key $i.$j.a.txt.cpabe.proxy" >> test_dec.sh
		echo "done" >> test_dec.sh 
	done
done

echo "cpabe-keygen pub_key master_key attr1 attr2 attr3 attr4 attr5 attr6 attr7 attr8 attr9 attr10 attr11 attr12 attr13 attr14 attr15 attr16 attr17 attr18 attr19 attr20 attr21 attr22 attr23 attr24 attr25 attr26 attr27 attr28 attr29 attr30 attr31 attr32 attr33 attr34 attr35 attr36 attr37 attr38 attr39 attr40 attr41 attr42 attr43 attr44 attr45 attr46 attr47 attr48 attr49 attr50 attr51 attr52 attr53 attr54 attr55 attr56 attr57 attr58 attr59 attr60 attr61 attr62 attr63 attr64 attr65 attr66 attr67 attr68 attr69 attr70 attr71 attr72 attr73 attr74 attr75 attr76 attr77 attr78 attr79 attr80 attr81 attr82 attr83 attr84 attr85 attr86 attr87 attr88 attr89 attr90 attr91 attr92 attr93 attr94 attr95 attr96 attr97 attr98 attr99 attr100" >> test_keygen.sh

echo "cpabe-revoke pub_key master_key" >> test_rvk.sh

# cpabe-setup
# cpabe-keygen pub_key master_key attr1 attr2 attr3 attr4 attr5 attr6 attr7 attr8 attr9 attr10 attr11 attr12 attr13 attr14 attr15 attr16 attr17 attr18 attr19 attr20 attr21 attr22 attr23 attr24 attr25 attr26 attr27 attr28 attr29 attr30 attr31 attr32 attr33 attr34 attr35 attr36 attr37 attr38 attr39 attr40 attr41 attr42 attr43 attr44 attr45 attr46 attr47 attr48 attr49 attr50 attr51 attr52 attr53 attr54 attr55 attr56 attr57 attr58 attr59 attr60 attr61 attr62 attr63 attr64 attr65 attr66 attr67 attr68 attr69 attr70 attr71 attr72 attr73 attr74 attr75 attr76 attr77 attr78 attr79 attr80 attr81 attr82 attr83 attr84 attr85 attr86 attr87 attr88 attr89 attr90 attr91 attr92 attr93 attr94 attr95 attr96 attr97 attr98 attr99 attr100
# u_k = cat cpabe_users
# cpabe-revoke pub_key master_key >> e_rvk.out
# cpabe-convert pub_key FILE.cpabe revoked_list $u_k
# cpabe-dec pub_key priv_key 40.a.txt.cpabe.proxy