#for TYPE in arista mlnx; do
for TYPE in mlnx arista; do
		
	FILENAME="${TYPE}_$(date +%F_%H-%M-%S).txt"
	echo -n > $FILENAME

	for i in $(find  routing/ redundancy/ switching/ tunneling/ management/ -type f -name \*cap);do
		python hostif-test.py $TYPE $i | tee -a $FILENAME
	done
done
