folderName="automactc"
prefix="automactc-output"
fmt="json"

pypath="/usr/bin/python"

tar xf $folderName.tar.gz
cd $folderName

sudo $pypath automactc.py --rtr --prefix $prefix -fmt $fmt -x quicklook coreanalytics safari

mv $prefix*.tar.gz ../.
cd ../
rm -rf $folderName
rm $folderName.tar.gz
rm deploy.sh
