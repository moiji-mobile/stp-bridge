#include <unistd.h>
#include <stdio.h>
#include <pti/NexusWare.h>

void InitHW(void)
{
  int status,i;

  /* configure the board clock */
  status = PTI_SetHSCMStandalone(0,PTI_CLK_TRUNK + 1,  PTI_CLK_NONE, 
      PTI_NETREF_2048K);
  if (status < 0) 
    fprintf(stderr, "Error: PTI_SetClocking() = %d\n", status);

  sleep(1);

  /* open the port devices */
  for (i=1; i<=8; i++)
  {
    status = PTI_SetT1Framing(i, PTI_FRAME_E1CRC, PTI_ENCODE_HDB3);
    if (status < 0)
      fprintf(stderr, "Error: PTI_SetFraming(%d) = %d\n", i, status);
  }

  /* configure PTMC */
  status = PTI_SetPTMCNetref(0, PTI_PTMC_NETREF_DISABLE);
  if (status < 0)
    fprintf(stderr, "Error: PTI_SetPTMCNetref() = %d\n", status);
  status = PTI_SetPTMCClockMode(0, PTI_PTMC_CLOCKMODE_H100);
  if (status < 0)
    fprintf(stderr, "Error: PTI_SetPTMCClockMode() = %d\n", status);
  status = PTI_SetEnetPortState(PTI_ENET_PORT_ID_PTMC+0, 
                                 PTI_ENET_PORT_STATE_ENABLE_ALL);
  if (status < 0)
    fprintf(stderr, "Error: PTI_SetEnetPortState() = %d\n", status);
  status = PTI_AddEnetRoute(PTI_ENET_PORT_ID_PTMC+0, PTI_ENET_PORT_ID_FRONT+0, 1);
  status |= PTI_AddEnetRoute(PTI_ENET_PORT_ID_PTMC+0, PTI_ENET_PORT_ID_REAR+0, 1);
  status |= PTI_AddEnetRoute(PTI_ENET_PORT_ID_PTMC+0, PTI_ENET_PORT_ID_LOCAL+0, 1);
  if (status < 0)
    fprintf(stderr, "Error: PTI_AddEnetRoute() = %d\n", status);

  status = PTI_ConnectHSCM(PTI_HSCM_TRUNK+1,30,PTI_HSCM_DATACHAN,0,1,1);
  if (status < 0)
    fprintf(stderr, "Error: PTI_ConnectHSCM() = %d\n", status);
  
  status = PTI_ConnectHSCM(PTI_HSCM_TRUNK+1, 0, PTI_HSCM_PTMC, 0, 30, 0);
  status |= PTI_ConnectHSCM(PTI_HSCM_PTMC, 128, PTI_HSCM_TRUNK+1, 0, 30, 0);
  if (status < 0)
    fprintf(stderr, "Error: PTI_ConnectHSCM() = %d\n", status);


}

