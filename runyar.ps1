$tempList = get-childitem -path C:\Users -directory | where {$_.PsIsContainer} | Select-Object Name
echo $tempList.Name >> UserOutput.txt
$p1 = "C:\Users\"
$p3 = "\AppData\Roaming"
$fomat = "Results for : "
$y1 = " against Scan 1"
$y2 = " against Scan 2"
$y3 = " against Scan 3"
$y4 = " against Scan 4"

ForEach ($line in Get-Content .\UserOutput.txt) {
     echo $fomat$line >> results.txt
    .\yara64.exe -c -r .\rOne.yar $line >> .\results.txt
    
    echo $foreach$usr$y3 >> results.txt
    .\yara64.exe -c -r .\rThree.yar $line >> .\results.txt
    
    echo $foreach$usr$y4 >> results.txt
    .\yara64.exe -c -r .\rfour.yar $line >> .\results.txt
}
 
