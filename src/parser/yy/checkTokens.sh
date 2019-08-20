for i in {1..400}
do

   #echo "$i"
   grep -o "= $i," /home/tadeas/yaramod/include/yaramod/types/literal.h | wc -l
done
