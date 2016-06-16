package radius



type LoraRadiusReply struct {
	EncryptedJoinAccept       []byte
	//JoinRequest				  []byte
	NwkSKey		 			  []byte
	AppSKey      			  []byte
}