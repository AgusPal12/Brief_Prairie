# MESP-Scripting-OS

## Script_1:

```powershell
# Comparer les KB que j'ai dans une tableau,  avec les KB que j'ai dans mon OS

$kbPresentes = Get-HotFix #variable avec la liste de KB dans mon OS

$Tableau = @($kbPresentes.HotFixID) #faire mode tableau 

$kbVerifier = @("KB5049622","KB5049625","KB5066835") # Tableau avec les KB à comparer

foreach ($kb in $kbVerifier) { # Pour chaque element de mon Tableau à comparer
    if ($kb -in $Tableau) { # Si il se trouve dans mon OS
        Write-Host $kb -ForegroundColor Green # L'affiche de couleur Vert
    }
    else {
        Write-Host "$kb" -ForegroundColor Red # Sinon, Rouge
    }

}

```

## Script_2:

```powershell
#Meme dynamique que dans le Sript_1 mais lis depuis un .txt les KB à comparer avec mon OS

$ListeText = Get-Content "C:\Users\agust\OneDrive\Escritorio\Agustin 1.0\Francia1\Emploi\Simplon\Briefs\Prairie\KB_List.txt"

$kbPresentes = Get-HotFix #variable avec la liste de KB dans mon OS

$Tableau = @($kbPresentes.HotFixID) #faire mode tableau 

foreach ($kb in $ListeText) { 
    if ($kb -in $Tableau) {
        Write-Host $kb -ForegroundColor Green
    }
    else {
        Write-Host "$kb" -ForegroundColor Red
    }

}
```

## Dans un contexte AD:

Sur un domaine il faut avoir les droits Administrateur et permettre l'execution de scripts powershell si on le fat par GPO.

- Il faudra pressier dans le script la cible ( une ou plusieurs machines).
- Par exemple :
  - Pour 1 machine :
    - `Get-Hotfix -ComputerName Nom_du_PC`
  - Pour plusieurs :
    - `$machines = @("PC1", "PC2", "PC3") #mets dans une variable la liste de machines`
    - ```powershell
      foreach (pc in pcinmachines) { #et en suite on fait la boucle pour obtenir le HotFixID
      Write-Host "`n$pc :"
      Get-HotFix -ComputerName $pc | Select-Object HotFixID
      }

      ```
- On applique la boucle, par exemple celle du Script_2 à l’intérieur de la boucle du script que cible les PCs du parque.
- Généralement on exporte les résultat dans un .csv pour une meilleur lisibilité à posteriori.

# Signature Script PowerShell

Certificat auto-signé car on est dans un environment de test ou lab, sinon il faut un certificat officiel auprès d’une autorité de certification (CA) interne (AD CS) ou publique.

## Creation du certificat :

`New-SelfSignedCertificate -Type CodeSigning -CertStoreLocation "Cert:\LocalMachine\My" -Subject "CN=Cert_PowerShell_Brief" -KeyLength 2048 -KeyAlgorithm RSA -NotAfter (Get-Date).AddYears(1)`

```
PS C:\WINDOWS\system32> `New-SelfSignedCertificate `-Type CodeSigning` -CertStoreLocation "Cert:\LocalMachine\My" -Subject "CN=Cert_PowerShell_Brief" -KeyLength 2048 -KeyAlgorithm RSA -NotAfter (Get-Date).AddYears(1)                                                                                                                                                                                                                                                                               PSParentPath : Microsoft.PowerShell.Security\Certificate::LocalMachine\My                                                                                                                                                                    Thumbprint                                Subject                                                                       ----------                                -------                                                                       A26FEBAE982A8C64066AFED82AEBB8618E8B004F  CN=CertificatAutosigneExercicePowerShell
```

## Signature des Scripts :

`Set-AuthenticodeSignature -FilePath "C:\Users\agust\OneDrive\Escritorio\Agustin 1.0\Francia1\Emploi\Simplon\Briefs\Prairie\Script_1.ps1" -Certificate (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=Cert_PowerShell_Brief"})`

![alt text](<Capture d'écran Signature.jpg>)

**Pour effacer un certificat** `Remove-Item -Path "Cert:\LocalMachine\My<Thumbprint>`

## Verification de signatures :

`Get-AuthenticodeSignature "C:\Users\agust\OneDrive\Escritorio\Agustin 1.0\Francia1\Emploi\Simplon\Briefs\Prairie\Brief_Prairie\Script_1.ps1"`


![alt text](<Capture d'écran Verification Signature.jpg>)