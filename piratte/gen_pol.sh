# generate random policies 10 for each no. of leaves per policy
# the generated policy in generated_policy.txt
for i in 1 5 10 15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90 95 100
do
	for j in 1 2 3 4 5 6 7 8 9 10
	do
		policy = gen_policy $i 
		echo $policy >> generated_policy.pol
	done
done