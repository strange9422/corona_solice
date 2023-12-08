function Main
{
    #------------------------------------------------------------------------------
	
	    $GLOBAL:ProjectPath		     = 'C:\FTP_SHARE' 
	    cd $GLOBAL:ProjectPath
		#----------------------------------------------------------------------------
		# Copy the latest good build to the local machine.
		$GLOBAL:SSPBuildPath         ="\\64.102.17.50\workgroup\cbabu-ssp\Published\12.6\"

		$GLOBAL:ICMBuildPath        = "\\64.102.17.50\workgroup\ccbu-latestbuilds\Published\ICM\"
		
		$GLOBAL:CVPBuildPath        = "\\64.102.17.50\workgroup\ccbu-latestbuilds\Published\CVP\12.6.3\"
		
		$ComponentName= $env:COMPONENT_NAME
		test-log "the component name is : $ComponentName"
		
		$SprintNo =$env:SSP_BUILD_SPRINT_NO
		test-log "The $ComponentName Sprint Number :$SprintNo "
		
		$extension = $env:file_extension
		test-log "The file extension is : $extension "

		$release_folder = $env:Release_Folder_Version
		test-log "The Release Version Folder is : $release_folder"
		
		$GLOBAL:BuildLocalPath =$env:BUILD_LOCAL_PATH
		test-log "Build local path ( where the latest build will download ) : $GLOBAL:BuildLocalPath "
		# test-log "url:$GLOBAL:ProjectPath $GLOBAL:SSPBuildPath"
		
		
		$DownloadBuildURL = $GLOBAL:SSPBuildPath+$SprintNo+'\'+$ComponentName+'\'
		if($ComponentName -eq "CVP"){
			$DownloadBuildURL = $GLOBAL:CVPBuildPath

		}
		test-log "DownloadURL :$DownloadBuildURL "

        $full_rtp_build_path = ""
		

		if($ComponentName -eq "ICM"){
			$DownloadBuildURL = $ICMBuildPath+$release_folder
			$latestICMFolder = Get-ChildItem -Path $DownloadBuildURL -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
			$DownloadBuildFolder = $DownloadBuildURL
			$DownloadBuildURL = $DownloadBuildURL+ '\' + $latestICMFolder + '\install\DVD.iso\'

			$latestIso = Get-ChildItem -Path $DownloadBuildURL -File | Where-Object { $_.Extension -eq ".iso" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            $full_rtp_build_path = $DownloadBuildURL + $latestIso
            test-log "Full RTP latest build path is : $full_rtp_build_path"

			#Check If latest ISO is already downloaded
			$path = $GLOBAL:BuildLocalPath + $latestIso
			$res =  test-path "$path"
			$result = 1

			if($res){
			
				#finding the date of creation of current rtp picking build
				$rtp_build_creation_date = (Get-Item -Path $full_rtp_build_path).CreationTime.Date
				test-log "Creation date of build stored in local is : $rtp_build_creation_date"
				
				#finding the date of creation of current local build
				$local_build_creation_date = (Get-Item -Path $path).CreationTime.Date
				test-log "Creation date of build taking from RTP server is : $local_build_creation_date"

				#comparing the date of creation of both the builds
				if($rtp_build_creation_date -eq $local_build_creation_date){
					$same_build = $true
					test-log "Build stored in local and rtp server is from same sprint.So,not downloading the same build again."
				 }
				else{
					$same_build = $false
					test-log "Build stored in local and rtp server is different.So, Proceeding to download the latest build."
				}
			  
				#if local path exists and builds in both location are from same sprint.
				if( $res -and $same_build -eq $true)
				{
					test-log "The latest build is already downloaded to $GLOBAL:BuildLocalPath"
					$result = 2
					exit 2
				}
			}

			if ($result -eq 1 )
			{
				#------------------------------------------------------------------------
				#Clearing out the previous local build iso
				$res = test-path "$GLOBAL:BuildLocalPath\"
				if( $res )
				{
					test-log "Clearing previous local build ISO from - $GLOBAL:BuildLocalPath"
					remove-item "$GLOBAL:BuildLocalPath\*"
				} 
			
				#Downloading the latest build
				test-log "Download ISO URL : $DownloadBuildURL"

                $filename = $latestIso.Basename

				robocopy $DownloadBuildURL $BuildLocalPath $latestIso

				$path = $GLOBAL:BuildLocalPath + $latestIso
			
				$res =  test-path "$path"
				
				if( $res )
				{
					test-log "Successfully downloaded ISO image $latestIso to - $GLOBAL:BuildLocalPath"
					exit 0
				}
			}

		}

		$path_res =test-path "$DownloadBuildURL"
		Write-Host $path_res
		
		if($path_res){
		
			if( $extension -eq "iso" ) {	
				$latestIso = Get-ChildItem -Path $DownloadBuildURL -File | Where-Object { $_.Extension -eq ".iso" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                $full_rtp_build_path = $DownloadBuildURL + $latestIso
                test-log "Full RTP latest build path is : $full_rtp_build_path"

				if ($latestIso) {
					test-log "Latest ISO: $($latestIso.Name)"
				} else {
					$latestFolder = Get-ChildItem -Path $DownloadBuildURL -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
					if ($latestFolder) {
						test-log "Latest Folder: $($latestFolder.Name)"
					} else {
						test-log "No ISO files or folders found in the directory."
					}
					$GLOBAL:BuildNumber = $latestFolder.Name
					test-log "Latest $ComponentName build & version is identified to be # $GLOBAL:BuildNumber"
					
					$isoPath =$DownloadBuildURL + $latestFolder
					test-log " RTP server path with latest folder : $isoPath " 
					
					$latestIso = Get-ChildItem -Path $isoPath -Filter "*.iso" | Sort-Object CreationTime -Descending | Select-Object -First 1
					test-log "$ComponentName build iso  image is identified to be $latestIso"

					$full_rtp_build_path = $isoPath +"\" + $latestIso
					test-log "Full RTP latest build path is : $full_rtp_build_path"
				}
			}
			elseif( $extension -eq "cop" ) { 
			
				$latestIso = Get-ChildItem -Path $DownloadBuildURL -Filter "*.cop.sgn" | Where-Object { $_.Name -notmatch "Rollback" } |Sort-Object CreationTime -Descending | Select-Object -First 1
				if($latestIso){
					test-log "latest cop file is : $latestIso "
				}
				$full_rtp_build_path = $DownloadBuildURL + $latestIso
                test-log "Full RTP latest build path is : $full_rtp_build_path"
				else {
				 
				}
			}
			elseif( $extension -eq "zip" ) {
				$GLOBAL:BuildNumber = ""
				$latestIso = Get-ChildItem -Path $DownloadBuildURL -Filter "*.zip" | Sort-Object CreationTime -Descending | Select-Object -First 1
				test-log "$ComponentName build ZIP file is identified to be : $latestIso "
				
				$full_rtp_build_path = $DownloadBuildURL + $latestIso
                test-log "Full RTP latest build path is : $full_rtp_build_path"
			}
			elseif($extension -eq "exe") {
				$GLOBAL:BuildNumber = ""
				$latestIso = Get-ChildItem -Path $DownloadBuildURL -Filter "*.exe" | Sort-Object CreationTime -Descending |
				Select-Object -First 1
				test-log "$ComponentName build exe  file is identified to be : $latestIso"
				
				$full_rtp_build_path = $DownloadBuildURL + $latestIso
                test-log "Full RTP latest build path is : $full_rtp_build_path"
			}
			
			#Check If latest ISO is already downloaded
			$path = $GLOBAL:BuildLocalPath + $latestIso
			$res =  test-path "$path"
			$result = 1
			
			#checking if the local build path exists, check for same builds. if path doesn't exists simply download the latest build from sprint.
			if($res){
			
				#finding the date of creation of current rtp picking build
				$rtp_build_creation_date = (Get-Item -Path $full_rtp_build_path).CreationTime.Date
				test-log "Creation date of build stored in local is : $rtp_build_creation_date"
				
				#finding the date of creation of current local build
				$local_build_creation_date = (Get-Item -Path $path).CreationTime.Date
				test-log "Creation date of build taking from RTP server is : $local_build_creation_date"

				#comparing the date of creation of both the builds
				if($rtp_build_creation_date -eq $local_build_creation_date){
					$same_build = $true
					test-log "Build stored in local and rtp server is from same sprint.So,not downloading the same build again."
				 }
				else{
					$same_build = $false
					test-log "Build stored in local and rtp server is different.So, Proceeding to download the latest build."
				}
			  
				#if local path exists and builds in both location are from same sprint.
				if( $res -and $same_build -eq $true)
				{
					test-log "The latest build is already downloaded to $GLOBAL:BuildLocalPath"
					$result = 2
					exit 2
				}
			}
			
			#if $res is false, means path doesn't exists means, build is not there already. Download the latest build from rtp server.
			if ($result -eq 1 )
			{
				#------------------------------------------------------------------------
				#Clearing out the previous local build iso
				$res = test-path "$GLOBAL:BuildLocalPath\"
				if( $res )
				{
					test-log "Clearing previous local build ISO from - $GLOBAL:BuildLocalPath"
					remove-item "$GLOBAL:BuildLocalPath\*"
				} 
				
				#------------------------------------------------------------------------
				#Downloading the latest build
				$url = $DownloadBuildURL + $GLOBAL:BuildNumber
				test-log "Download ISO URL : $url"

                    $filename = $latestIso.Basename
                    

				robocopy $url $GLOBAL:BuildLocalPath $latestIso
				$path = $GLOBAL:BuildLocalPath + $latestIso
			
				$res =  test-path "$path"
				
				if( $res )
				{
					test-log "Successfully downloaded ISO image $latestIso to - $GLOBAL:BuildLocalPath"
					exit 0
				}
				
				
				
			}
		}
		else{
		
		    test-log "Given $ComponentName Build is not available in the path:  $DownloadBuildURL "
			test-log ""
			exit 1
		}		


	
	
}



function test-log( $TestLogStr )
{
	$TestLogFile = $GLOBAL:ProjectPath + 'CC_BuildDownload' + '.log'
	$TestLogString = ((get-date).ToString() + ' - ' + $TestLogStr)
	add-content -path $TestLogFile -value $TestLogString
	write-host $TestLogString
}
	
	

. Main
