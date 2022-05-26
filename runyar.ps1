$tempList = get-childitem -path C:\Users -directory | where {$_.PsIsContainer} | Select-Object Name
$p1 = "C:\Users\"
$p3 = "\AppData\Roaming"
$fomat = "Results for : "
$y1 = " against Scan 1"
$y2 = " against Scan 2"
$y3 = " against Scan 3"
$y4 = " against Scan 4"

ForEach ($user in $tempList) {
    $path =  ("C:\Users\" + $user.Name + $p3)
    $usr = $user.Name

    echo $foreach$usr$y1 >> results.txt
    .\yara64.exe -c -r .\rOne.yar $path >> .\results.txt

    echo $foreach$usr$y2 >> results.txt
    .\yara64.exe -c -r .\rTwo.yar $path >> .\results.txt

    echo $foreach$usr$y3 >> results.txt
    .\yara64.exe -c -r .\rThree.yar $path >> .\results.txt
    
    echo $foreach$usr$y4 >> results.txt
    .\yara64.exe -c -r .\rfour.yar $path >> .\results.txt
}